# SPDX-License-Identifier: GPL-3.0-or-later
"""Serialize, reopen and reject damaged records from actual source-route runs."""
import argparse
import copy
import json
from pathlib import Path
import re

from ipv4_source_route.controls import decode, fingerprint, require
from ipv4_source_route.corpus import checksum, option_fields
from ipv4_source_route.wire_evidence import observations, router, verify
from tcp6.inputs import digest, write


def controls(native, guest, output, *, applications=False, queues=False):
    require(not (applications and queues), 'one complete wire-control workload')
    require(not output.exists(), 'new retained wire-reader control directory')
    output.mkdir(parents=True)
    validate = observations
    verify_capture = verify
    if applications:
        from ipv4_source_route.applications import definitions, observations as application_observations, compare
        compare(native, guest)
        validate = application_observations
        verify_capture = lambda directory: verify(directory, definitions=definitions(), observe=validate)
    if queues:
        from ipv4_source_route.queues import definitions, reader
        verify_capture = lambda directory: verify(directory, definitions=definitions(), observe=reader(directory))
    receipts = []
    for is_native, directory in ((True, native), (False, guest)):
        verify_capture(directory)
        if queues:
            validate = reader(directory)
        original = {name: digest(directory / name) for name in ('client.log', 'wire.json', 'results.json')}
        text = (directory / 'client.log').read_text()
        wire = decode((directory / 'wire.json').read_text())
        results = decode((directory / 'results.json').read_text())
        prefix = 'native-' if is_native else 'guest-'

        def rejected(label, name, changed):
            # Keep the small exact edit and changed-document hash. Reopen the
            # complete serialized document before checking it, then retire only
            # that temporary copy; originals and every rejection remain pinned.
            path = output / (prefix + label + '.damaged')
            content = changed if name == 'client.log' else json.dumps(changed)
            path.write_text(content)
            reopened = path.read_text()
            value = reopened if name == 'client.log' else decode(reopened)
            try:
                validate(value if name == 'client.log' else text,
                         value if name == 'wire.json' else wire,
                         value if name == 'results.json' else results, is_native)
            except (ValueError, KeyError, TypeError) as error:
                receipt = dict(label=prefix + label, document=name, original_sha256=original[name],
                               damaged_sha256=fingerprint(content.encode()), error=str(error))
            else:
                raise ValueError('accepted damaged source-route evidence: ' + path.name)
            if name == 'client.log':
                before, after = text.splitlines(), content.splitlines()
                receipt['lines'] = dict(before=before, after=after)
            elif name == 'wire.json':
                receipt['rows'] = [dict(index=at, before=wire[at] if at < len(wire) else None,
                                       after=changed[at] if at < len(changed) else None)
                                   for at in range(max(len(wire), len(changed)))
                                   if at >= min(len(wire), len(changed)) or wire[at] != changed[at]]
            else:
                receipt['rows'] = [dict(index=at, before=results[at] if at < len(results) else None,
                                       after=changed[at] if at < len(changed) else None)
                                   for at in range(max(len(results), len(changed)))
                                   if at >= min(len(results), len(changed)) or results[at] != changed[at]]
            write(output / (prefix + label + '.json'), receipt)
            path.unlink()
            receipts.append({key: value for key, value in receipt.items() if key not in ('rows', 'lines')})

        def rejected_documents(label, changes, expected_error):
            require(set(changes) <= set(original), 'known serialized timing-control documents')
            reopened, documents, paths = {}, {}, []
            for name, changed in changes.items():
                content = changed if name == 'client.log' else json.dumps(changed)
                path = output / (prefix + label + '-' + name + '.damaged')
                path.write_text(content)
                value = path.read_text()
                reopened[name] = value if name == 'client.log' else decode(value)
                documents[name] = dict(original_sha256=original[name], damaged_sha256=digest(path), after=content)
                paths.append(path)
            try:
                validate(reopened.get('client.log', text), reopened.get('wire.json', wire),
                         reopened.get('results.json', results), is_native)
            except (ValueError, KeyError, TypeError) as error:
                require(expected_error in str(error), 'timing fault must reach its intended validation gate: ' + str(error))
                message = str(error)
            else:
                raise ValueError('accepted damaged timing evidence: ' + prefix + label)
            receipt = dict(label=prefix + label, document='multiple', error=message, documents=documents)
            path = output / (prefix + label + '.json')
            write(path, receipt)
            for temporary in paths:
                temporary.unlink()
            receipts.append(dict(label=receipt['label'], document='multiple', error=message, patch_sha256=digest(path)))

        def retimed(number, knots):
            changed = copy.deepcopy(wire)
            require(all(right[0] > left[0] and right[1] > left[1] for left, right in zip(knots, knots[1:])),
                    'ordered timing-control anchors')
            for row in changed:
                if row['case'] != number:
                    continue
                timestamp = row['monotonic_ns']
                for (old_begin, new_begin), (old_end, new_end) in zip(knots, knots[1:]):
                    if old_begin <= timestamp <= old_end:
                        row['monotonic_ns'] = new_begin + (timestamp - old_begin) * (new_end - new_begin) // (old_end - old_begin)
                        break
            return changed

        for number in range(len(results)):
            changed = copy.deepcopy(results)
            changed[number]['observation_seconds'] -= 1
            rejected('short-observation-' + str(number), 'results.json', changed)
            changed = copy.deepcopy(results)
            changed[number]['ended_ns'] = changed[number]['observation_began_ns'] + 1000
            rejected('short-elapsed-' + str(number), 'results.json', changed)
        for at, value in enumerate(wire):
            frame = bytearray.fromhex(value['frame'])
            if value['direction'] != 'output' or not router(frame, value['index']) or frame[12:14] != b'\x08\x00':
                continue
            changed = copy.deepcopy(wire)
            frame[22] ^= 1  # TTL: retain a valid checksum to exercise byte equality.
            frame[24:26] = bytes(2)
            frame[24:26] = checksum(bytes(frame[14:14 + (frame[14] & 15) * 4])).to_bytes(2, 'big')
            changed[at]['frame'] = frame.hex()
            rejected('wire-ttl-' + str(at), 'wire.json', changed)
            frame = bytearray.fromhex(value['frame'])
            if applications and frame[23] == 17:
                header = (frame[14] & 15) * 4
                data = frame[14 + header:14 + int.from_bytes(frame[16:18], 'big')]
                data[6:8] = bytes(2)
                destination = bytes((10, 0, 0, 2)) if is_native else frame[30:34]
                pseudo = frame[26:30] + destination + bytes((0, 17)) + len(data).to_bytes(2, 'big')
                data[6:8] = (checksum(bytes(pseudo + data)) or 65535).to_bytes(2, 'big')
                frame[14 + header:14 + header + len(data)] = data
                changed = copy.deepcopy(wire)
                changed[at]['frame'] = frame.hex()
                rejected('wrong-checksum-destination-' + str(at), 'wire.json', changed)
                frame = bytearray.fromhex(value['frame'])
            for option, kind, _ in option_fields(frame[14:]):
                if kind != 68:
                    continue
                stamp = 14 + option + frame[14 + option + 2] - 5
                ms = int.from_bytes(frame[stamp:stamp + 4], 'big')
                frame[stamp:stamp + 4] = ((ms + 60000) % 86400000).to_bytes(4, 'big')
                frame[24:26] = bytes(2)
                frame[24:26] = checksum(bytes(frame[14:14 + (frame[14] & 15) * 4])).to_bytes(2, 'big')
                changed = copy.deepcopy(wire)
                changed[at]['frame'] = frame.hex()
                rejected('wire-source-clock-' + str(at), 'wire.json', changed)
        records = text.splitlines()
        stems = ['WIRE_' + stem for stem in ('KERNEL', 'READY', 'CLOCK', 'OBSERVED', 'PASS')]
        stems += (['APP_' + stem for stem in ('OPTIONS', 'OPEN', 'PEER', 'CONTROL', 'ACCEPT', 'DATA', 'RECEIVED', 'CLOSED')]
                  if applications else ['WIRE_MUTATED', 'WIRE_RAW', 'WIRE_RAW_BYTES'])
        if queues:
            stems += ['ALIAS', 'SAMPLE', 'DRAINED']
        for stem in stems:
            candidates = [at for at, line in enumerate(records) if line.startswith('IPV4_SOURCE_' + stem + ' ')]
            require(candidates, 'actual control record exists')
            at = candidates[0]
            rejected('missing-' + stem.lower(), 'client.log', '\n'.join(records[:at] + records[at + 1:]) + '\n')
            rejected('duplicate-' + stem.lower(), 'client.log', '\n'.join(records[:at] + [records[at]] + records[at:]) + '\n')
        rejected('failed', 'client.log', text + f'\nIPV4_SOURCE_WIRE_FAIL case={len(results) - 1} operation=injected errno=1\n')
        rejected('wrong-kernel', 'client.log', text.replace('sysname=Linux', 'sysname=Axiom64') if is_native else
                 text.replace('sysname=Axiom64', 'sysname=Linux'))
        for name in ('case', 'index', 'monotonic_ns'):
            changed = copy.deepcopy(wire)
            changed[0][name] = False
            rejected('boolean-' + name, 'wire.json', changed)
        if queues:
            rejected('missing-result', 'results.json', results[:-1])
            rejected('duplicate-result', 'results.json', results + [results[0]])
            for number, result in enumerate(results):
                changed = copy.deepcopy(results)
                changed[number]['packets'] = bool(result['packets'])
                rejected('boolean-packet-count-' + str(number), 'results.json', changed)
                if result['sample_requests']:
                    changed = copy.deepcopy(results)
                    changed[number]['sample_requests'][0]['responded_ns'] = (
                        changed[number]['sample_requests'][0]['requested_ns'] + 1000000001)
                    rejected('late-sample-response-' + str(number), 'results.json', changed)
            stems = ('SYNC', 'RAW_CLOCK', 'ADDRESS', 'GUARD_ARM', 'GUARD')
            for stem in stems:
                at = next(at for at, line in enumerate(records) if line.startswith('IPV4_SOURCE_' + stem + ' '))
                rejected('missing-' + stem.lower(), 'client.log', '\n'.join(records[:at] + records[at + 1:]) + '\n')
                rejected('duplicate-' + stem.lower(), 'client.log', '\n'.join(records[:at] + [records[at]] + records[at:]) + '\n')
            number = next(row['case'] for row in definitions() if row['name'] == 'arp-failure-pending-loose')
            arp = [value['monotonic_ns'] for value in wire if value['case'] == number and value['direction'] == 'output' and
                   value['index'] == 1 and value['frame'][24:28] == '0806' and value['frame'][12:24] == '020000000002']
            require(len(arp) == 3, 'actual original three-retry timing control')
            ended = results[number]['ended_ns']
            changed = retimed(number, [(arp[0], arp[0]), (arp[1], arp[0] + 100000000),
                                      (arp[2], arp[0] + 200000000), (ended, ended)])
            rejected_documents('compressed-retries', {'wire.json': changed}, 'actual one-second ARP retry spacing')
            upper = 2100000000
            changed = retimed(number, [(arp[0], arp[0]), (arp[1], arp[0] + upper + 200000000),
                                      (arp[2], arp[0] + upper + 1200000000), (ended, ended)])
            rejected_documents('late-retry', {'wire.json': changed}, 'actual one-second ARP retry spacing')
            number = next(row['case'] for row in definitions() if row['name'] == 'arp-failure-ordinary-transit')
            third = [value['monotonic_ns'] for value in wire if value['case'] == number and value['direction'] == 'output' and
                     value['index'] == 1 and value['frame'][24:28] == '0806' and value['frame'][12:24] == '020000000002'][2]
            emitted = next(value['monotonic_ns'] for value in wire if value['case'] == number and value['direction'] == 'output' and
                           value['frame'][24:28] == '0800' and router(bytes.fromhex(value['frame']), value['index']))
            for label, delay in (('early-wire-error', 100000000), ('late-wire-error', 2500000000)):
                changed = retimed(number, [(third, third), (emitted, third + delay),
                                          (results[number]['ended_ns'], results[number]['ended_ns'])])
                rejected_documents(label, {'wire.json': changed}, 'actual ICMP error follows the third ARP retransmission timer')
            number = next(row['case'] for row in definitions() if row['name'] == 'arp-failure-complete-loose')
            pattern = re.compile(rf'^(IPV4_SOURCE_RAW_CLOCK case={number} packet=1 mode=poll realtime_ns=)(\d+) '
                                 r'monotonic_before_ns=(\d+) monotonic_after_ns=(\d+) empty_before_ns=(\d+)$', re.M)
            require(pattern.search(text), 'actual polled local error clock for timing controls')
            for label, delta in (('early-local-error', -2000000000), ('late-local-error', 1500000000)):
                def moved(match):
                    return (match[1] + str(int(match[2]) + delta) + ' monotonic_before_ns=' + str(int(match[3]) + delta) +
                            ' monotonic_after_ns=' + str(int(match[4]) + delta) + ' empty_before_ns=' + str(int(match[5]) + delta))
                changed_text = pattern.sub(moved, text)
                changed_results = copy.deepcopy(results)
                changed_results[number]['raw_receipts'][1]['monotonic_ns'] += delta
                rejected_documents(label, {'client.log': changed_text, 'results.json': changed_results},
                                   'local raw error follows the third ARP retransmission timer')
            guard_pattern = re.compile(rf'^IPV4_SOURCE_GUARD case={number} packets=1 revents=0$', re.M)
            require(guard_pattern.search(text), 'actual empty local raw guard for controls')
            for label, replacement in (('early-ready-delayed-consumer', f'IPV4_SOURCE_GUARD case={number} packets=1 revents=1'),
                                       ('guard-after-normal-error', f'IPV4_SOURCE_GUARD case={number} packets=2 revents=0')):
                rejected_documents(label, {'client.log': guard_pattern.sub(replacement, text)},
                                   'actual empty raw guard before local error')
            changed_results = copy.deepcopy(results)
            changed_results[number]['error_guard']['requested_ns'] -= 200000000
            changed_results[number]['error_guard']['responded_ns'] -= 200000000
            rejected_documents('early-empty-guard', {'results.json': changed_results},
                               'causal empty guard follows the third ARP retransmission timer')
            rejected('manual-local-error', 'client.log', pattern.sub(lambda match: match[0].replace('mode=poll', 'mode=command'), text))
        require(original == {name: digest(directory / name) for name in original}, 'original complete evidence unchanged')
    proof = dict(passed=True, serialized_reopened_controls=len(receipts), original_evidence_unchanged=True, results=receipts)
    write(output / 'results.json', proof)
    return {key: value for key, value in proof.items() if key != 'results'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native', type=Path)
    parser.add_argument('guest', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--applications', action='store_true')
    parser.add_argument('--queues', action='store_true')
    args = parser.parse_args()
    print(json.dumps(controls(args.native, args.guest, args.output, applications=args.applications, queues=args.queues)), flush=True)


if __name__ == '__main__':
    main()

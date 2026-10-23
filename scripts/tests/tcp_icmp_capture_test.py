# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain synchronized corruptions of actual ICMP captures and reject each one."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_clock_mutations import candidate_auditor
from fetch import ROOT
from tcp_icmp_capture import audit_row, checksum, contract, fnv, require


def records(path):
    raw = path.read_bytes()
    require(raw[:4] == bytes.fromhex('d4c3b2a1'), 'actual little-endian PCAP')
    at, rows = 24, []
    while at < len(raw):
        seconds, micros, size, original = struct.unpack_from('<IIII', raw, at)
        require(size == original and at + 16 + size <= len(raw), 'complete original PCAP')
        rows.append(dict(stamp=seconds * 1000000 + micros, frame=raw[at + 16:at + 16 + size]))
        at += 16 + size
    return raw[:24], rows


def write_capture(path, header, rows):
    data = bytearray(header)
    for row in rows:
        frame, stamp = row['frame'], row['stamp']
        data += struct.pack('<IIII', stamp // 1000000, stamp % 1000000, len(frame), len(frame)) + frame
    path.write_bytes(data)


def repair(frame, quote=False):
    frame = bytearray(frame)
    if quote:
        offset = 42
        size = (frame[offset] & 15) * 4
        frame[offset + 10:offset + 12] = bytes(2)
        frame[offset + 10:offset + 12] = checksum(frame[offset:offset + size]).to_bytes(2, 'big')
    if frame[23] == 1:
        frame[36:38] = bytes(2)
        frame[36:38] = checksum(frame[34:]).to_bytes(2, 'big')
    else:
        frame[50:52] = bytes(2)
        frame[50:52] = checksum(frame[26:34] + bytes([0, 6]) +
                                (len(frame) - 34).to_bytes(2, 'big') + frame[34:]).to_bytes(2, 'big')
    return bytes(frame)


def mutations(build, row, lane, destination, cases):
    names = [row['log'], row['peer'], row['inputs'], *row['captures']]
    names += [value['monotonic_receipts'] for value in row.get('capture_statistics', [])]
    originals = {name: (build / name).read_bytes() for name in names}
    header, capture = records(build / row['captures'][lane])
    ipv4 = [(index, item) for index, item in enumerate(capture) if item['frame'][12:14] == b'\x08\x00']
    own_mac = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    ordinal = {case['name']: index for index, case in enumerate(cases)}

    def port(case):
        return 48000 + lane * 1000 + ordinal[case]

    def icmp(case):
        return next((index, item) for index, item in ipv4 if item['frame'][23] == 1 and
                    int.from_bytes(item['frame'][64:66], 'big') == port(case))

    def receipt(text, frame, occurrence=0):
        matches = list(re.finditer(r'^ICMP_FRAME lane=' + str(lane) + r' index=\d+ length=\d+ kind=\d+ '
                                  r'hash=' + fnv(frame) + r' monotonic_ms=(\d+) '
                                  r'packet_realtime_ns=(\d+) dequeue_ms=\d+\r?$', text, re.M))
        require(len(matches) > occurrence, 'original actual driver receipt to damage')
        return matches[occurrence]

    results = []

    def reject(kind, transform):
        # Only the quote-before-SYN control may reschedule copied receipt
        # pairs. Other clock corruptions must retain their native rejection;
        # original observations and packet timestamps remain untouched.
        checked = candidate_auditor(audit_row, build, row,
                                    reschedule_reordered=(kind == 'noncausal-error'))
        with tempfile.TemporaryDirectory(prefix='axiom64-icmp-damage-') as temporary:
            folder = Path(temporary)
            for name, data in originals.items():
                (folder / name).write_bytes(data)
            transform(folder)
            try:
                checked(folder, row, cases)
            except ValueError as error:
                reason = str(error)
                if kind == 'noncausal-error':
                    require('quote' in reason and 'clock' not in reason,
                            'noncausal ICMP control reaches its original quote ownership guard: ' + reason)
            else:
                raise AssertionError(f'synchronized ICMP damage accepted: {kind}')
            retained_names = names
            if 'client_namespace' in row:
                (folder / 'candidate-row.json').write_text(json.dumps(checked.last_row, indent=2) + '\n')
                retained_names = [*names, 'candidate-row.json']
            label = Path(row['log']).stem + f'-lane{lane}-{kind}'
            archive = destination / (label + '.zip')
            with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as retained:
                for name in retained_names:
                    retained.write(folder / name, name)
            files = {name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in retained_names}
            with zipfile.ZipFile(archive) as retained:
                require(retained.testzip() is None and all(
                    hashlib.sha256(retained.read(name)).hexdigest() == digest for name, digest in files.items()),
                    'every retained synchronized damage archive has exact bytes and valid CRCs')
            results.append(dict(kind=kind, lane=lane, report=row['log'], archive=archive.name,
                                sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                                files=files, rejection=reason))

    def synchronized(folder, index, modified, move_before=None):
        rows = copy.deepcopy(capture)
        frame = rows[index]['frame']
        occurrence = sum(item['frame'] == frame for item in rows[:index])
        peers = json.loads((folder / row['peer']).read_text())
        peer = next(value for value in peers if value['lane'] == lane)
        matching = [at for at, item in enumerate(peer['frames']) if item['frame'] == frame.hex()]
        peer_at = matching[occurrence]
        text = (folder / row['log']).read_text()
        match = receipt(text, frame, occurrence)
        if modified is None:
            rows.pop(index)
            peer['frames'].pop(peer_at)
            text = text[:match.start()] + text[match.end():]
            expression = r'(^ICMP_CAPTURE_PASS lane=' + str(lane) + r' index=\d+ packets=)(\d+)( dropped=0 ipv4=)(\d+)'
            text = re.sub(expression, lambda value: value[1] + str(int(value[2]) - 1) +
                          value[3] + str(int(value[4]) - 1), text, flags=re.M)
        else:
            rows[index]['frame'] = modified
            peer['frames'][peer_at]['frame'] = modified.hex()
            updated = re.sub(r'length=\d+', 'length=' + str(len(modified)), match[0])
            updated = updated.replace(fnv(frame), fnv(modified))
            text = text[:match.start()] + updated + text[match.end():]
        if move_before is not None:
            # Move all three actual observer records ahead of the SYN. Repaired
            # counters and hashes alone cannot prove a causally owned quote.
            source = rows[move_before]
            moved = rows.pop(index)
            moved['stamp'] = source['stamp'] - 1
            rows.insert(move_before, moved)
            source_peer = next(at for at, item in enumerate(peer['frames']) if item['frame'] == source['frame'].hex())
            moved_peer = peer['frames'].pop(peer_at)
            moved_peer['ms'] = peer['frames'][source_peer]['ms'] - .001
            peer['frames'].insert(source_peer, moved_peer)
            source_receipt = receipt(text, source['frame'])
            moved_receipt = receipt(text, frame)
            line = re.sub(r'monotonic_ms=\d+', 'monotonic_ms=' + source_receipt[1], moved_receipt[0])
            line = re.sub(r'packet_realtime_ns=\d+', 'packet_realtime_ns=' + source_receipt[2], line)
            text = text[:moved_receipt.start()] + text[moved_receipt.end():]
            source_receipt = receipt(text, source['frame'])
            text = text[:source_receipt.start()] + line + '\n' + text[source_receipt.start():]
        write_capture(folder / row['captures'][lane], header, rows)
        (folder / row['peer']).write_text(json.dumps(peers, indent=2) + '\n')
        (folder / row['log']).write_text(text)

    index, item = icmp('port')
    wrong_code = bytearray(item['frame'])
    wrong_code[35] = 1
    reject('wrong-error', lambda folder: synchronized(folder, index, repair(wrong_code)))
    wrong_sequence = bytearray(item['frame'])
    wrong_sequence[66:70] = ((int.from_bytes(wrong_sequence[66:70], 'big') + 1000) &
                             0xffffffff).to_bytes(4, 'big')
    reject('unowned-sequence', lambda folder: synchronized(folder, index, repair(wrong_sequence)))
    wrong_address = bytearray(item['frame'])
    wrong_address[57] ^= 1
    reject('unowned-address', lambda folder: synchronized(folder, index, repair(wrong_address, quote=True)))
    reject('omitted-error', lambda folder: synchronized(folder, index, None))
    source_at = next(at for at, source in ipv4 if source['frame'][23] == 6 and
                     source['frame'][6:12] == own_mac and source['frame'][14:42] == item['frame'][42:70])
    reject('noncausal-error', lambda folder: synchronized(folder, index, item['frame'], move_before=source_at))

    cycle_port = 49000 + lane * 1000
    syns = [(at, item) for at, item in ipv4 if item['frame'][23] == 6 and item['frame'][6:12] == own_mac and
            item['frame'][47] == 2 and int.from_bytes(item['frame'][36:38], 'big') == cycle_port]
    second_at, second = syns[1]
    stale_at, stale = next((at, item) for at, item in ipv4 if at > second_at and item['frame'][23] == 1 and
                          item['frame'][42:70] == syns[0][1]['frame'][14:42])
    changed = bytearray(stale['frame'])
    changed[66:70] = second['frame'][38:42]
    reject('stale-as-current', lambda folder: synchronized(folder, stale_at, repair(changed)))

    progress_at, progress = next((at, item) for at, item in ipv4 if item['frame'][23] == 6 and
                                item['frame'][6:12] != own_mac and
                                int.from_bytes(item['frame'][34:36], 'big') == port('progress-clears') and
                                item['frame'][-1:] == b'K')
    changed = bytearray(progress['frame'])
    changed[42:46] = ((int.from_bytes(changed[42:46], 'big') + 1) & 0xffffffff).to_bytes(4, 'big')
    reject('poisoned-progress', lambda folder: synchronized(folder, progress_at, repair(changed)))
    reject('omitted-progress', lambda folder: synchronized(folder, progress_at, None))

    def shorten(folder):
        text = (folder / row['log']).read_text()
        expression = (r'(^ICMP_CASE_PASS lane=' + str(lane) + ' case=' + str(ordinal['soft-port']) +
                      r' name=soft-port elapsed_ms=)\d+( start_ms=)(\d+)( end_ms=)\d+')
        text, count = re.subn(expression, lambda value: value[1] + '500' + value[2] + value[3] +
                             value[4] + str(int(value[3]) + 500), text, flags=re.M)
        require(count == 1, 'actual timeout clock marker to damage')
        (folder / row['log']).write_text(text)
    reject('shortened-timeout', shorten)

    def forged_input(folder):
        inputs = json.loads((folder / row['inputs']).read_text())
        name = next(name for name in inputs['products'] if name.endswith('tcp-icmp-' + row['linkage']))
        inputs['products'][name] = '0' * 64
        (folder / row['inputs']).write_text(json.dumps(inputs, indent=2) + '\n')
    reject('forged-product', forged_input)
    companion_at, companion = next((at, item) for at, item in ipv4 if item['frame'][23] == 6 and
                                  item['frame'][6:12] != own_mac and
                                  int.from_bytes(item['frame'][34:36], 'big') == 47000 + lane * 1000 and
                                  item['frame'][-1:] == b'Q')
    reject('omitted-companion', lambda folder: synchronized(folder, companion_at, None))

    def damage_clock(folder, kind):
        text = (folder / row['log']).read_text()
        match = receipt(text, item['frame'])
        if kind == 'forged-arrival-mapping':
            dequeue = re.search(r'dequeue_ms=(\d+)', match[0])[1]
            damaged = re.sub(r'monotonic_ms=\d+', 'monotonic_ms=' + str(int(dequeue) + 1000), match[0])
        elif kind == 'missing-packet-timestamp':
            damaged = re.sub(r' packet_realtime_ns=\d+ dequeue_ms=\d+', '', match[0])
        elif kind == 'arrival-after-dequeue':
            damaged = re.sub(r'dequeue_ms=\d+', 'dequeue_ms=0', match[0])
        elif kind == 'unarmed-observer':
            expression = r'(^ICMP_CAPTURE_READY lane=' + str(lane) + r' index=\d+ timestamp_error=)2'
            text, count = re.subn(expression, r'\g<1>0', text, flags=re.M)
            require(count == 1, 'actual timestamp arming observation to damage')
            (folder / row['log']).write_text(text)
            return
        else:
            anchor = re.search(r'^ICMP_CAPTURE_CLOCK phase=end .*$', text, re.M)
            if kind == 'missing-clock-anchor':
                damaged = ''
            else:
                damaged = re.sub(r'realtime_ns=(\d+)',
                                 lambda value: 'realtime_ns=' + str(int(value[1]) + 1000000000), anchor[0])
            text = text[:anchor.start()] + damaged + text[anchor.end():]
            (folder / row['log']).write_text(text)
            return
        text = text[:match.start()] + damaged + text[match.end():]
        (folder / row['log']).write_text(text)

    for kind in ('forged-arrival-mapping', 'missing-packet-timestamp', 'arrival-after-dequeue',
                 'missing-clock-anchor', 'stepped-arrival-clock', 'unarmed-observer'):
        reject(kind, lambda folder, kind=kind: damage_clock(folder, kind))
    require(len(results) == 17, 'all synchronized quote, control, clock and input damage cases')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', action='append', help='partial development reports; default requires the full matrix')
    args = parser.parse_args()
    build = ROOT / 'build'
    destination = build / 'tcp-icmp-damaged'
    destination.mkdir(exist_ok=True)
    reports = args.report or ['tcp-icmp-native-results.json', 'tcp-icmp-results.json']
    all_rows = [(name, row) for name in reports for row in json.loads((build / name).read_text())]
    if not args.report:
        natives = [row for _, row in all_rows if 'client_namespace' in row]
        guests = [row for _, row in all_rows if 'client_namespace' not in row]
        require(len(natives) == 3 and {row['linkage'] for row in natives} == {'native', 'static', 'dynamic'} and
                len(guests) == 8 and {(row['linkage'], row['firmware'], row['transport']) for row in guests} ==
                {(linkage, firmware, transport) for linkage in ('static', 'dynamic')
                 for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')},
                'all three native linkages and all eight guest configurations')
    cases, negatives = contract(), []
    for name, row in all_rows:
        audit_row(build, row, cases)
        for lane in range(2):
            negatives += mutations(build, row, lane, destination, cases)
    result = dict(passed=True, captures=len(all_rows) * 2, negative_cases=len(negatives), cases=negatives,
                  reports={name: hashlib.sha256((build / name).read_bytes()).hexdigest() for name in reports})
    (destination / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'TCP_ICMP_CAPTURE_CHECKER_PASS captures={result["captures"]} negative_cases={len(negatives)}')


if __name__ == '__main__':
    main()

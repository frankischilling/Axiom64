# SPDX-License-Identifier: GPL-3.0-or-later
"""Damage copies of real captures and require the independent reader to reject them."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct

from http_download.audit import fingerprint, guest_log, sources, verify as audit
from http_download.wire import verify as wire
from tcp_capture import checksum
from tcp_fault_capture import require


def damaged_capture(data, port, repair_checksum):
    data = bytearray(data)
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    at = 24
    while at < len(data):
        length = struct.unpack_from(endian+'I', data, at+8)[0]
        at += 16
        start, end = at, at+length
        frame = data[start:end]
        at = end
        if len(frame) < 54 or frame[12:14] != b'\x08\x00' or frame[23] != 6:
            continue
        ip_length = (frame[14] & 15)*4
        tcp_at = 14+ip_length
        source = struct.unpack_from('!H', frame, tcp_at)[0]
        tcp_length = (frame[tcp_at+12] >> 4)*4
        ip_total = struct.unpack_from('!H', frame, 16)[0]
        if source != port or ip_total-ip_length-tcp_length < 1000:
            continue
        # Change actual server HTTP body bytes, leaving all PCAP lengths intact.
        data[start+tcp_at+tcp_length+500] ^= 1
        if repair_checksum:
            segment_at, segment_end = start+tcp_at, start+14+ip_total
            struct.pack_into('!H', data, segment_at+16, 0)
            pseudo = frame[26:34]+struct.pack('!BBH', 0, 6, segment_end-segment_at)
            struct.pack_into('!H', data, segment_at+16, checksum(pseudo+data[segment_at:segment_end]))
            require(checksum(pseudo+data[segment_at:segment_end]) == 0, 'control has a valid changed TCP checksum')
        return bytes(data)
    raise ValueError('actual capture lacks the large HTTP response needed by the damage control')


def verify(directory, output, selectors, baseline=None):
    """Retain each damaged input and rejection, with the actual originals unchanged."""
    output.mkdir(parents=True, exist_ok=False)
    if baseline is None:
        baseline = audit(directory, **selectors)
    (output / 'baseline.json').write_text(json.dumps(baseline, indent=2)+'\n')
    case = directory / baseline['rows'][0]['profile']
    original = case / 'lane0.pcap'
    result = json.loads((case / 'result.json').read_text())
    peers = result['peers']['0']
    originals = {path: fingerprint(path) for path in
                 (original, case / 'result.json', case / 'guest.log', directory / 'source-inputs.json')}
    capture_bytes = original.read_bytes()
    rows = []
    for name in ('changed-tcp-checksum', 'changed-http-body-valid-checksum', 'missing-capture',
                 'truncated-capture', 'changed-native-request', 'missing-profile', 'changed-retained-source',
                 'missing-guest-log', 'changed-guest-tls-file-hash', 'guest-panic-with-success',
                 'wrong-guest-firmware'):
        control = output / name
        control.mkdir()
        changed = control / 'lane0.pcap'
        expected = copy.deepcopy(peers)
        guest_row = copy.deepcopy(result)
        if name in ('changed-tcp-checksum', 'changed-http-body-valid-checksum'):
            changed.write_bytes(damaged_capture(capture_bytes, peers['http']['port'],
                                               name == 'changed-http-body-valid-checksum'))
        elif name == 'truncated-capture':
            changed.write_bytes(capture_bytes[:-17])
        elif name == 'changed-native-request':
            request = bytearray.fromhex(expected['http']['requests'][0]['request'])
            request[5] ^= 1
            expected['http']['requests'][0]['request'] = request.hex()
            changed.write_bytes(capture_bytes)
        elif name == 'missing-profile':
            for profile in baseline['rows'][1:]:
                (control / profile['profile']).mkdir()
        elif name == 'changed-retained-source':
            shutil.copyfile(directory / 'source-inputs.json', control / 'source-inputs.json')
            shutil.copytree(directory / 'retained-source', control / 'retained-source')
            source = control / 'retained-source/scripts/http_download/client.py'
            source.write_bytes(source.read_bytes()+b'\n# damaged retained source\n')
        elif name in ('changed-guest-tls-file-hash', 'guest-panic-with-success', 'wrong-guest-firmware'):
            raw = (case / 'guest.log').read_bytes()
            if name == 'changed-guest-tls-file-hash':
                modified = raw.replace(b'DOWNLOAD_HASH tls13.bin d', b'DOWNLOAD_HASH tls13.bin e', 1)
            elif name == 'guest-panic-with-success':
                modified = raw+b'\nPANIC: actual-log damage control\n'
            else:
                old = b'Firmware: '+result['firmware'].upper().encode()
                modified = raw.replace(old, b'Firmware: '+(b'UEFI' if result['firmware'] == 'bios' else b'BIOS'), 1)
            require(modified != raw, 'actual guest record changed for semantic damage control')
            (control / 'guest.log').write_bytes(modified)
            # Repair the raw fingerprint too, so a semantic check must reject it.
            guest_row['process']['log_input'] = fingerprint(control / 'guest.log')
        (control / 'peers.json').write_text(json.dumps(expected, indent=2)+'\n')
        try:
            if name == 'missing-profile':
                audit(control, **selectors)
            elif name == 'changed-retained-source':
                sources(control)
            elif name in ('missing-guest-log', 'changed-guest-tls-file-hash', 'guest-panic-with-success',
                          'wrong-guest-firmware'):
                guest_log(control, guest_row)
            else:
                wire(changed, 0, expected)
        except (ValueError, RuntimeError, FileNotFoundError, KeyError, struct.error) as error:
            observation = dict(control=name, rejected=True, reason=str(error))
            (control / 'rejection.json').write_text(json.dumps(observation, indent=2)+'\n')
            rows.append(observation)
        else:
            raise RuntimeError('damaged actual evidence was accepted: '+name)
    require(all(fingerprint(path) == value for path, value in originals.items()),
            'original actual evidence remains unchanged after damage controls')
    return dict(passed=True, controls=rows, original_actual_evidence_unchanged=True,
                selected_profile=case.name, baseline_profiles=baseline['profiles'],
                original_capture_sha256=hashlib.sha256(capture_bytes).hexdigest())

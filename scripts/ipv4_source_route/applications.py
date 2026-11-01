# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared UDP/TCP source-route inputs and independent application/wire checks."""
import argparse
import json
from pathlib import Path
import re

from ipv4_source_route.controls import require
from ipv4_source_route.corpus import cases as fixed, checksum
from ipv4_source_route.packets import client_trace, clocks, normalized


def transport(row, flags=2, acknowledgement=0, data=b'', sequence=None):
    base = bytes.fromhex(row['base'])
    ip = bytearray(base[14:14 + (base[14] & 15) * 4])
    ip[4:6] = (0x7800 + row['case']).to_bytes(2, 'big')
    ports = row['peer_port'].to_bytes(2, 'big') + row['port'].to_bytes(2, 'big')
    if row['protocol'] == 17:
        content = bytearray(ports + (8 + len(data)).to_bytes(2, 'big') + bytes(2) + data)
        offset = 6
    else:
        sequence = row['sequence'] if sequence is None else sequence
        content = bytearray(ports + sequence.to_bytes(4, 'big') + acknowledgement.to_bytes(4, 'big') +
                            bytes((0x50, flags)) + b'\x40\x00' + bytes(4) + data)
        offset = 16
    ip[9] = row['protocol']
    pseudo = ip[12:20] + bytes((0, ip[9])) + len(content).to_bytes(2, 'big')
    content[offset:offset + 2] = (checksum(bytes(pseudo + content)) or 65535).to_bytes(2, 'big')
    ip[2:4] = (len(ip) + len(content)).to_bytes(2, 'big')
    ip[10:12] = bytes(2)
    ip[10:12] = checksum(bytes(ip)).to_bytes(2, 'big')
    return base[:14] + ip + content


def definitions():
    bases = {row['name']: row for row in fixed()}
    rows = []
    for action in ('udp-closed', 'tcp-closed', 'udp-return', 'tcp-accept'):
        for strict in (False, True):
            number = len(rows)
            base = bases['complete-strict' if strict else 'complete-loose']['input']
            protocol = 17 if action.startswith('udp') else 6
            row = dict(name=action + ('-strict' if strict else '-loose'), case=number, kind='packet', clocked=False,
                       action=action, port=32000 + number, peer_port=40000 + number, sequence=0x10203040 + number * 4096,
                       protocol=protocol, base=base, policy={}, raw_inputs=[])
            data = b'AXIOM64_SOURCE_UDP' + bytes((0, number)) if protocol == 17 else b''
            row['transmitted'] = [transport(row, data=data).hex()]
            row['payload'] = (data if protocol == 17 else b'AXIOM64_SOURCE_TCP' + bytes((0, number))).hex()
            rows.append(row)
    for strict in (False, True):
        for ecn in (1, 2, 3):
            number = len(rows)
            base = bytearray.fromhex(bases['complete-strict' if strict else 'complete-loose']['input'])
            base[15] = 0x28 | ecn
            row = dict(name='tcp-closed-' + ('strict' if strict else 'loose') + '-ecn' + str(ecn), case=number,
                       kind='packet', clocked=False, action='tcp-closed', port=32000 + number, peer_port=40000 + number,
                       sequence=0x10203040 + number * 4096, protocol=6, base=base.hex(), policy={}, raw_inputs=[], payload='')
            row['transmitted'] = [transport(row).hex()]
            rows.append(row)
    for strict in (False, True):
        number = len(rows)
        row = dict(name='udp-return-bound-' + ('strict' if strict else 'loose'), case=number, kind='packet', clocked=False,
                   action='udp-return', bound=True, port=32000 + number, peer_port=40000 + number, sequence=0,
                   protocol=17, base=bases['complete-strict' if strict else 'complete-loose']['input'], policy={}, raw_inputs=[])
        data = b'AXIOM64_SOURCE_UDP' + bytes((0, number))
        row['transmitted'] = [transport(row, data=data).hex()]
        row['payload'] = data.hex()
        rows.append(row)
    return rows


def application_records(text, rows):
    actual = [[] for _ in rows]
    for line in text.replace('\r\n', '\n').splitlines():
        if not line.startswith('IPV4_SOURCE_APP_'):
            continue
        match = re.fullmatch(r'IPV4_SOURCE_APP_([A-Z]+) case=(\d+) ?(.*)', line)
        require(match and int(match[2]) < len(rows), 'complete known application record')
        fields = {}
        for field in match[3].split():
            pair = field.split('=', 1)
            require(len(pair) == 2 and pair[0] not in fields, 'complete unique application field')
            fields[pair[0]] = pair[1]
        actual[int(match[2])].append((match[1], fields))
    for row, values in zip(rows, actual):
        action = row['action']
        if action.endswith('closed'):
            require(not values, 'closed transport has no application description')
            continue
        require(len(values) >= 2 and values[1][0] == 'OPEN', 'actual application opening')
        opened = values[1][1]
        require(set(opened) == {'kind', 'port', 'ingress'} and opened['ingress'].isdigit() and
                0 < int(opened['ingress']) < 1 << 31, 'actual independently reported ingress index')
        route = bytes((137 if 'strict' in row['name'] else 131, 7, 4, 10, 1, 0, 2, 0)).hex()
        def options(owner, phase, data):
            return 'OPTIONS', dict(owner=owner, phase=phase, bytes=str(len(bytes.fromhex(data))), data=data)
        def record(label, **fields):
            return label, {key: str(value) for key, value in fields.items()}
        kind = 'tcp' if row['protocol'] == 6 else 'udp-bound' if row.get('bound') else 'udp'
        expected = [options('listener', 'open', '' if kind == 'tcp' else '01010101'),
                    record('OPEN', kind=kind, port=row['port'], ingress=opened['ingress'])]
        if kind == 'tcp':
            expected += [record('ACCEPT', source='0a000002', source_port=row['peer_port'],
                                local='0a000001', local_port=row['port']),
                         options('accepted', 'before', route), options('accepted', 'after', route),
                         record('DATA', kind='tcp', bytes=len(bytes.fromhex(row['payload'])), data=row['payload'])]
        else:
            processed = bytearray.fromhex(route)
            processed[2] = 8
            info = int(opened['ingress']).to_bytes(4, 'little') + bytes.fromhex('0a0000010a000001')
            expected += [record('PEER', source='0a000002', port=row['peer_port']),
                         record('DATA', kind='udp', bytes=len(bytes.fromhex(row['payload'])), data=row['payload']),
                         record('CONTROL', level=0, kind=8, bytes=12, data=info.hex()),
                         record('CONTROL', level=0, kind=6, bytes=8, data=processed.hex()),
                         record('CONTROL', level=0, kind=7, bytes=8, data=route),
                         options('listener', 'after', '01010101')]
        expected += [('RECEIVED', {}), ('CLOSED', {})]
        require(values == expected, 'all actual payload, peer, return-control and description-owned option bytes')
    return actual


def observations(text, wire, results, native):
    rows = definitions()
    require(client_trace(text, rows, native) == [[] for _ in rows], 'complete application client and raw observations')
    application_records(text, rows)
    require(type(results) is list and len(results) == len(rows) and type(wire) is list,
            'complete actual application result and wire matrices')
    last = -1
    for value in wire:
        require(set(value) == {'case', 'index', 'direction', 'frame', 'monotonic_ns', 'realtime_ns', 'packet_type'} and
                type(value['case']) is int and 0 <= value['case'] < len(rows) and
                type(value['index']) is int and value['index'] in (0, 1) and value['direction'] in ('input', 'output') and
                type(value['monotonic_ns']) is int and last <= value['monotonic_ns'] < 1 << 63 and
                type(value['realtime_ns']) is int and 0 <= value['realtime_ns'] < 1 << 63 and
                isinstance(value['frame'], str) and re.fullmatch(r'[0-9a-f]{28,131106}', value['frame']) and
                len(value['frame']) % 2 == 0, 'complete bounded ordered original application Ethernet record')
        last = value['monotonic_ns']
        packet_type = value['packet_type']
        require(packet_type is None or
                (native and value['direction'] == 'output' and type(packet_type) is int and 0 <= packet_type <= 4),
                'actual native application packet-socket metadata')
    summaries, packets = [], 0
    for row, result in zip(rows, results):
        require(type(result['case']) is int and result['case'] == row['case'] and result['name'] == row['name'] and
                type(result['observation_seconds']) is int and result['observation_seconds'] == 1 and
                all(type(result[key]) is int and 0 <= result[key] < 1 << 63
                    for key in ('input_began_ns', 'observation_began_ns', 'ended_ns')) and
                result['input_began_ns'] <= result['observation_began_ns'] <= result['ended_ns'] and
                result['ended_ns'] - result['observation_began_ns'] >= 1000000000,
                'complete application case and original full observation')
        require(result['raw_inputs'] == [] and result['source_clocks'] == clocks(text, row['case'], len(rows)) and
                result['clock_request_ns'] is result['clock_response_ns'] is None and result['timestamp_receipts'] == [] and
                result['matched_native_reference'] is None, 'actual complete application observation metadata')
        values = [value for value in wire if value['case'] == row['case']]
        inputs = [value for value in values if value['direction'] == 'input' and value['frame'][24:28] == '0800']
        require(inputs and inputs[0]['frame'] == row['transmitted'][0] and
                all(value['index'] == 0 and result['input_began_ns'] <= value['monotonic_ns'] <= result['ended_ns']
                    for value in inputs), 'actual original transport request and ingress')
        outputs, declared, segment_data, server_isn, finished, mss, peer_acks = [], [], b'', None, False, None, []
        for value in values:
            frame, index = bytes.fromhex(value['frame']), value['index']
            if value['direction'] != 'output' or frame[6:12] != bytes((2, 0, 0, 0, 0, index + 1)):
                continue
            if frame[12:14] == b'\x08\x06':
                require(len(frame) >= 42 and frame[14:22] == bytes.fromhex('0001080006040001') and
                        frame[38:42] == bytes((10, index, 0, 2)), 'actual application next-hop ARP ownership')
                continue
            if frame[12:14] != b'\x08\x00':
                continue
            require(result['input_began_ns'] <= value['monotonic_ns'] <= result['ended_ns'],
                    'actual transport output within its complete observation')
            ethernet, decoded = normalized(frame)
            declared.append(dict(index=index,ethernet=ethernet.hex(),ip=decoded.hex()))
            ip = bytearray(decoded)
            header = (ip[0] & 15) * 4
            expected_route = bytes((137 if 'strict' in row['name'] else 131, 7, 4, 10, 0, 0, 2, 0))
            source = bytes.fromhex('0a010001' if row['action'] == 'udp-return' and not row.get('bound') else '0a000001')
            require(index == 1 and ethernet == bytes.fromhex('0200000001020200000000020800') and
                    header == 28 and ip[20:header] == expected_route and ip[12:16] == source and
                    ip[16:20] == bytes((10, 1, 0, 2)) and ip[8] == 64, 'exact reverse-route IPv4 and Ethernet fields')
            data = bytearray(ip[header:])
            if row['action'] == 'udp-closed':
                require(ip[9] == 1 and ip[1] == 0xc8 and ip[6:8] == bytes(2) and
                        checksum(bytes(data)) == 0 and data[:2] == bytes((3, 3)), 'actual reversed UDP port-unreachable')
                original = bytes.fromhex(row['transmitted'][0])[14:]
                require(data[8:] == original and data[4:8] == bytes(4), 'complete original UDP error quote')
            else:
                protocol = row['protocol']
                require(ip[9] == protocol and ip[6:8] == b'\x40\x00', 'actual transport protocol and DF policy')
                require(data[:4] == row['port'].to_bytes(2, 'big') + row['peer_port'].to_bytes(2, 'big'),
                        'actual response port tuple')
                destination = ip[16:20] if native and protocol == 17 else bytes((10, 0, 0, 2))
                pseudo = ip[12:16] + destination + bytes((0, protocol)) + len(data).to_bytes(2, 'big')
                require(checksum(bytes(pseudo + data)) == 0, 'actual complete transport checksum with its stated destination')
                if protocol == 17:
                    # The measured Linux UDP path checksums its first hop. The
                    # guest uses the final recipient, as required for delivery
                    # after the source route is consumed. Validate each before
                    # comparing the remaining complete packet bytes.
                    require(ip[1] == 0 and len(data) >= 8 and data[4:6] == len(data).to_bytes(2, 'big') and
                            data[6:8] != bytes(2) and data[8:].hex() == row['payload'], 'actual UDP reply and complete payload')
                    ip[header + 6:header + 8] = bytes(2)
                else:
                    require(len(data) >= 20 and 20 <= (data[12] >> 4) * 4 <= len(data), 'complete actual TCP header')
                    flags, sequence = data[13], int.from_bytes(data[4:8], 'big')
                    acknowledgement = int.from_bytes(data[8:12], 'big')
                    body = bytes(data[(data[12] >> 4) * 4:])
                    require(data[12] & 15 == 0 and data[18:20] == bytes(2), 'bounded TCP reserved and urgent fields')
                    if row['action'] == 'tcp-closed':
                        require(ip[1] == 0x28 and len(data) == 20 and flags == 20 and sequence == 0 and
                                acknowledgement == row['sequence'] + 1 and data[14:16] == bytes(2),
                                'exact reflected DSCP, cleared ECN and closed-port reset')
                    else:
                        require(ip[1] == 0 and flags in (16, 17, 18, 24, 25) and
                                int.from_bytes(data[14:16], 'big') > 0, 'valid accepted-stream flags and receive window')
                        if flags & 2:
                            require(server_isn is None and not body and acknowledgement == row['sequence'] + 1 and
                                    data[20:] == bytes.fromhex('02040218'), 'actual SYN-ACK and option-adjusted MSS')
                            server_isn, mss = sequence, 536
                        else:
                            require(server_isn is not None and data[12] >> 4 == 5 and
                                    acknowledgement == row['sequence'] + 2 + len(bytes.fromhex(row['payload'])),
                                    'actual acknowledgement of peer data and half-close')
                            if not body and not flags & 1:
                                require(sequence == (server_isn + 1 + len(segment_data) + finished) & 0xffffffff,
                                        'actual pure acknowledgement sequence')
                            if body:
                                require(not finished and sequence == (server_isn + 1 + len(segment_data)) & 0xffffffff,
                                        'contiguous actual server payload sequence')
                                segment_data += body
                            if flags & 1:
                                require(not finished and sequence + len(body) ==
                                        (server_isn + 1 + len(bytes.fromhex(row['payload']))) & 0xffffffff,
                                        'actual FIN after the complete server payload')
                                finished = True
                        if flags & 3 or body:
                            peer_sequence = row['sequence'] + 1 if flags & 2 else row['sequence'] + 2 + len(bytes.fromhex(row['payload']))
                            peer_acks.append(transport(row, flags=16,
                                acknowledgement=(sequence + len(body) + bool(flags & 1) + bool(flags & 2)) & 0xffffffff,
                                sequence=peer_sequence).hex())
            outputs.append((index, ethernet.hex(), bytes(ip).hex()))
        require(type(result['packets']) is int and len(outputs) == result['packets'] and outputs,
                'all actual output packets and declared count')
        require(result['output_packets'] == declared, 'all retained producer packet declarations match actual original wire bytes')
        if row['action'] == 'tcp-accept':
            require(mss == 536 and finished and segment_data.hex() == row['payload'], 'actual accepted-stream echo and complete close')
            data = transport(row, flags=25, acknowledgement=(server_isn + 1) & 0xffffffff,
                             sequence=row['sequence'] + 1, data=bytes.fromhex(row['payload'])).hex()
            require([value['frame'] for value in inputs] == [row['transmitted'][0], peer_acks[0], data, *peer_acks[1:]],
                    'all original peer handshake, data, FIN and acknowledgement bytes')
            summaries.append(dict(case=row['case'],name=row['name'],kind='stream',payload=segment_data.hex(),mss=mss,
                                  return_options=expected_route.hex()))
        else:
            require(len(outputs) == 1 and len(inputs) == 1, 'one exact request and response for the datagram/reset case')
            summaries.append(dict(case=row['case'],name=row['name'],kind='packet',packets=outputs))
        packets += len(outputs)
    if not native:
        lines = text.replace('\r\n', '\n').splitlines()
        require(lines.count('AXIOM64_TESTS_PASS') == lines.count('AXIOM64_EXIT status=0') == 1,
                'actual application and guest init success')
    return dict(cases=len(rows),packets=packets,raw_packets=0,timestamp_cases=0,semantics=summaries,
                udp_checksum_destination='first-hop-native' if native else 'final-recipient-guest')


def compare(native, guest):
    from ipv4_source_route.controls import decode
    from ipv4_source_route.wire_evidence import verify
    native, guest = Path(native), Path(guest)
    left = verify(native, definitions=definitions(), observe=observations)
    right = verify(guest, definitions=definitions(), observe=observations)
    require(left['mode'] == 'native' and right['mode'] == 'guest' and
            left['semantics'] == right['semantics'], 'same complete native and guest application semantics')
    compiled = [decode((directory / 'program.inputs.json').read_text()) for directory in (native, guest)]
    require(compiled[0]['sources'] == compiled[1]['sources'], 'same complete application probe sources')
    if left['profile'] == right['profile']:
        require(left['program_sha256'] == right['program_sha256'], 'same actual native and guest executable')
    return dict(passed=True, cases=left['cases'], native_packets=left['packets'], guest_packets=right['packets'],
                native=left, guest=right, full_source_route_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('native', type=Path)
    parser.add_argument('guest', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    proof = compare(args.native, args.guest)
    if args.output:
        require(not args.output.exists(), 'new retained application readback')
        args.output.write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({key: value for key, value in proof.items() if key not in ('native', 'guest')}), flush=True)


if __name__ == '__main__':
    main()

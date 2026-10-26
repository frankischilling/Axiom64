# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen the original native primer packets, policy and release ordering."""
import copy
import json
from pathlib import Path
import struct
import zipfile
from ipv4_expiry_capture import checksum
from tcp_capture_clock import raw_records, bind_native_clock


def require(value, reason):
    if not value:
        raise ValueError('native ICMP preflight capture: '+reason)


def ip(frame):
    require(len(frame) >= 34 and frame[12:14] == b'\x08\0', 'original Ethernet IPv4 frame')
    packet = frame[14:]
    total = int.from_bytes(packet[2:4],'big')
    require(20 <= total <= len(packet) and packet[0] == 0x45 and not checksum(packet[:20]),
            'complete original IPv4 header and checksum')
    return packet[:total]


def audit(lanes, proof):
    require(set(proof) == {'schema','passed','held','releases','policy_before','policy_after','request','response'} and
            type(proof['schema']) is int and proof['schema'] == 1 and proof['passed'] is True,
            'complete successful raw preflight receipt')
    request, response = proof['request'], proof['response']
    lane = request['lane']
    require(type(lane) is int and lane in (0,1) and response['lane'] == lane, 'one original selected interface')
    guest, peer = bytes([0x52,0x54,0,0x12,0x34,0x10+lane]), bytes([2,0x41,0x58,0x49,0x50,lane])
    remote, local = bytes([10,23,lane+1,1]), bytes([10,23,lane+1,2])
    inputs, outputs, incoming = [], [], []
    for number, rows in enumerate(lanes):
        for row in rows:
            frame = row['frame']
            if len(frame) < 34 or frame[12:14] != b'\x08\0':
                continue
            packet = frame[14:]
            if packet[12:20] == bytes([10,23,number+1,1,10,23,number+1,2]):
                if packet[4:6] == struct.pack('!H',0x7b00+number):
                    inputs.append((number,row))
                else:
                    incoming.append((number,row))
            elif (packet[9] == 1 and packet[20:22] == b'\x03\x03' and
                  packet[32:34] == struct.pack('!H',0x7b00+number)):
                outputs.append((number,row))
    require(len(inputs) == len(outputs) == 1 and inputs[0][0] == outputs[0][0] == lane,
            'one independently captured request and one actual quote')
    first, last = inputs[0][1], outputs[0][1]
    require(first['frame'].hex() == request['frame_hex'] and last['frame'].hex() == response['frame_hex'],
            'raw primer receipt matches the original packet bytes')
    original, quote = ip(first['frame']), ip(last['frame'])
    require(first['frame'][:12] == guest+peer and len(original) == 28 and
            original[:2] == b'\x45\0' and original[4:10] == struct.pack('!HHBB',0x7b00+lane,0,51,17) and
            original[12:20] == remote+local and original[20:] == struct.pack('!HHHH',61398,61399,8,0),
            'exact owned closed-port UDP request')
    require(last['frame'][:12] == peer+guest and len(quote) == 56 and quote[:2] == b'\x45\xc0' and
            quote[6:10] == b'\0\0\x40\x01' and quote[12:20] == local+remote and
            quote[20:22] == b'\x03\x03' and not checksum(quote[20:]) and
            quote[24:28] == b'\0'*4 and quote[28:] == original,
            'actual complete error quote, route and checksums')
    expected = {'icmp_ratelimit':'1000\n','icmp_ratemask':'6168\n',
                'icmp_msgs_per_sec':'1000\n','icmp_msgs_burst':'50\n'}
    for name in ('policy_before','policy_after'):
        require(proof[name]['values'] == expected, 'original default rate policy at '+name)
    clock = lambda row:row['monotonic_ns']
    require(proof['policy_before']['monotonic_ns'] <= request['begin_ns'] <= clock(first) < clock(last) <=
            response['observed_ns'] <= proof['policy_after']['monotonic_ns'] and
            clock(first) <= request['capture_observed_ns'] <= request['end_ns'] and
            response['observed_ns']-request['begin_ns'] <= 2000000000,
            'actual unchanged packet clocks bracket the acknowledged preflight')
    held, released = proof['held'], proof['releases']
    require(0 < len(held) == len(released) <= 64, 'bounded complete original control release')
    for original_control, release in zip(held,released):
        number = original_control['lane']
        require(type(number) is int and number in (0,1) and release['lane'] == number and
                original_control['frame_hex'] == release['frame_hex'], 'original held bytes released without change')
        matches = [row for row in lanes[number] if row['frame'].hex() == original_control['frame_hex']]
        require(len(matches) == 1, 'each held original control exists once in the independent capture')
        control = ip(matches[0]['frame'])
        require(control[24:26] == b'FR' and control[26:28] == b'\0\0' and
                clock(matches[0]) <= original_control['observed_ns'] <= response['observed_ns'] <= release['begin_ns'],
                'first original fragment controls wait for the actual error')
    release_times = {row['lane']:row['begin_ns'] for row in released}
    require(incoming and all(clock(row) >= release_times.get(number,clock(last)+1) and
                             clock(row) > clock(last) for number,row in incoming),
            'original peer workload starts after the acknowledged native error')
    return dict(passed=True, lane=lane, held_controls=len(held), actual_requests=1, actual_quotes=1,
                quote_bytes=len(quote)-28, default_rate_policy_unchanged=True,
                original_packet_times_not_rescaled=True, original_controls_released_byte_identically=True)


def damaged_controls(lanes, proof, path):
    mutations={
        'missing-request':lambda data:data.__setitem__('request',None),
        'missing-response':lambda data:data.__setitem__('response',None),
        'changed-request':lambda data:data['request'].__setitem__('frame_hex','00'+data['request']['frame_hex'][2:]),
        'changed-quote':lambda data:data['response'].__setitem__('frame_hex','00'+data['response']['frame_hex'][2:]),
        'changed-rate-policy':lambda data:data['policy_before']['values'].__setitem__('icmp_msgs_per_sec','0\n'),
        'changed-final-policy':lambda data:data['policy_after']['values'].__setitem__('icmp_ratemask','0\n'),
        'missing-held-control':lambda data:data['held'].clear(),
        'missing-release':lambda data:data['releases'].clear(),
        'premature-release':lambda data:data['releases'][0].__setitem__('begin_ns',data['request']['begin_ns']),
        'changed-release':lambda data:data['releases'][0].__setitem__('frame_hex','00'+data['releases'][0]['frame_hex'][2:]),
        'wrong-lane':lambda data:data['response'].__setitem__('lane',1-data['request']['lane']),
        'false-pass':lambda data:data.__setitem__('passed',False)}
    verdicts={}
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,change in mutations.items():
            altered=copy.deepcopy(proof)
            change(altered)
            member=name+'.json'
            archive.writestr(member,json.dumps(altered))
            try:
                audit(lanes,json.loads(archive.read(member)))
            except (ValueError,KeyError,TypeError,IndexError) as error:
                verdicts[name]=str(error)
            else:
                raise ValueError('native ICMP preflight damaged control passed: '+name)
    require(len(verdicts)==12, 'all serialized damaged preflight receipts reopened and rejected')
    return verdicts


def verify_capture(directory, statistics, *, damage_archive=None):
    directory = Path(directory)
    path = directory/'native-icmp-preflight.json'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576,
            'bounded original preflight evidence')
    lanes, clocks = [], []
    require(len(statistics) == 2, 'both original native capture statistics')
    for lane in range(2):
        path = directory/f'lane{lane}.pcap'
        rows = list(raw_records(path))
        selected = [row for row in rows if len(row['frame']) >= 34 and row['frame'][12:14] == b'\x08\0']
        clocks.append(bind_native_clock(path,selected,statistics[lane]))
        lanes.append(selected)
    proof = json.loads((directory/'native-icmp-preflight.json').read_text())
    result = audit(lanes,proof)
    result['clocks'] = clocks
    if damage_archive is not None:
        result['damaged_controls'] = damaged_controls(lanes,proof,damage_archive)
    return result

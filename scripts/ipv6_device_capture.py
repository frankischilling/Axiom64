# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind original device inventories to both adapters' untouched packet clocks."""
import hashlib
import ipaddress
import json
import re
import struct

from ipv6_router_capture import checksum, qemu_records, require
from tcp_capture_clock import microseconds
from ipv6_device_frames import _mld, decode

ACTIONS = ('administrative', 'mtu', 'carrier')
HELLO, BEGIN, ADDRESS, SUMMARY, ARM, CHANGE, LINK, SECRET, END, FINISH, READY = range(11)


def plan(action):
    result = [(HELLO, 0), (BEGIN, 0), (READY, 0), (SECRET, 0), (LINK, 0), (ADDRESS, 0),
              (SUMMARY, 0), (ARM, 0)]
    if action == 'carrier':
        result.append((CHANGE, 0))
    for stage in (1, 2):
        result.append((LINK, stage))
        if action == 'carrier':
            result.append((ADDRESS, stage))
        result.append((SUMMARY, stage))
    result.append((ARM, 1))
    if action == 'carrier':
        result.append((CHANGE, 1))
    result += [(LINK, 3), (READY, 3), (SECRET, 4), (LINK, 4), (ADDRESS, 4), (SUMMARY, 4),
               (END, 0), (FINISH, 0)]
    return result


def inspect(path, lane, text, action, native=False, statistics=None, native_kernel_release=None):
    require(lane in (0, 1) and action in ACTIONS, 'known device subject and action')
    require(not native or isinstance(native_kernel_release, str) and native_kernel_release,
            'actual native device comparison kernel')
    parsed, clocks = decode(path, text, action, [plan(action)], native, statistics)
    requests = parsed[1 - lane]['requests']
    replies = parsed[1 - lane]['replies']
    probes = parsed[lane]['probes']

    def one(kind, stage):
        values = [value for value in requests if (value['kind'], value['stage']) == (kind, stage)]
        require(len(values) == 1, 'one selected actual device observation')
        return values[0]

    def moment(value):
        return microseconds(value['row'])

    def ack(value):
        return microseconds(replies[value['phase']])

    for stage in (0, 1, 2, 3, 4):
        value = one(LINK, stage)
        down = stage in (1, 2)
        flags = 0x1002 if down and action == 'administrative' else 0x1003 if down and action == 'carrier' else 0x1043
        require((value['flags'], value['preferred'], value['valid'], value['target']) ==
                (flags, 1279 if down and action == 'mtu' else 1500,
                 int(not (down and action == 'mtu')), bytes(16)),
                'actual raw link flags, MTU and IPv6 scope follow the selected transition')
    inventories = {}
    for stage in (0, 1, 2, 4):
        values = [value for value in requests if (value['kind'], value['stage']) == (ADDRESS, stage)]
        summary = one(SUMMARY, stage)
        count = int(stage in (0, 4) or action == 'carrier')
        require((summary['flags'], summary['preferred'], summary['valid'], summary['target']) ==
                (count, count, 0, bytes(16)) and len(values) == count,
                'actual complete device address and connected-prefix inventories')
        for value in values:
            require(value['flags'] == 0x880 and value['preferred'] == value['valid'] == 0xffffffff and
                    ipaddress.IPv6Address(value['target']).is_link_local,
                    'actual ready permanent stable link-local address flags and lifetimes')
        inventories[stage] = values
    old, current = inventories[0][0], inventories[4][0]
    for stage, address in ((0, old), (3, current)):
        ready = one(READY, stage)
        require(all(ready[key] == address[key] for key in ('flags', 'preferred', 'valid', 'target')),
                'first actual ready query equals the later complete owner inventory')
    require((old['target'] != current['target']) == (action == 'mtu'),
            'MTU recreation uses the new default key; preserved scopes retain their key')
    if action == 'carrier':
        require(all(inventories[stage][0]['target'] == old['target'] for stage in (1, 2)),
                'carrier loss preserves the actual ready owner')
    for stage in (0, 4):
        value = one(SECRET, stage)
        expected_secret = ipaddress.IPv6Address('fd00::100' if action == 'mtu' and stage == 4 else
                                               'fd00::' + str(10 + lane)).packed
        require((value['flags'], value['preferred'], value['valid'], value['target']) ==
                (0, 0, 0, expected_secret), 'captured actual stable-key readback for this scope lifetime')
    down, observed, restored, final = one(SUMMARY, 1), one(LINK, 2), one(ARM, 1), one(LINK, 4)
    require(moment(observed) - ack(down) >= 4000000 and
            observed['guest_ns'] - down['guest_ns'] >= 4000000000,
            'full real four-second unavailable interval follows actual query and ACK')
    require(moment(final) - ack(one(READY, 3)) >= 4000000 and
            final['guest_ns'] - one(READY, 3)['guest_ns'] >= 4000000000,
            'full real four-second restored observation')
    require(len(probes) == (1 if action == 'carrier' else 2), 'exact DAD budget across the device transition')
    first = probes[0]
    require(first['target'] == old['target'] and ack(one(BEGIN, 0)) <= microseconds(first['row']) < moment(old),
            'initial queried ready owner completed its original captured DAD')
    require(first['nonce'] != bytes(6) and
            1000000 <= moment(one(READY, 0)) - microseconds(first['row']) <= 2100000,
            'original initial DAD completes within the real one-to-two-point-one-second bound')
    require(not any(ack(down) <= microseconds(probe['row']) <= moment(restored) for probe in probes),
            'no DAD packet during the complete actual unavailable observation')
    if action != 'carrier':
        second = probes[1]
        require(second['target'] == current['target'] and
                ack(restored) <= microseconds(second['row']) < moment(current),
                'exactly one fresh DAD after administrative or MTU restoration')
        require(first['nonce'] != second['nonce'] and first['nonce'] != bytes(6) and second['nonce'] != bytes(6),
                'fresh nonzero enhanced DAD nonce for the recreated owner')
        require(1000000 <= moment(one(READY, 3)) - microseconds(second['row']) <= 2100000,
                'original restored DAD completes within the real one-to-two-point-one-second bound')
    marker = f'IPV6_DEVICE_PASS adapters=2 action={action} state=ready quiet_seconds=4'
    require(text.splitlines().count(marker) == 1 and
            not any(word in text for word in ('IPV6_DEVICE_FAIL', 'PANIC:', 'FAULT pid=')),
            'one complete successful actual device client')
    if action == 'carrier':
        carrier = json.loads((path.parent / 'carrier.json').read_text())
        require(carrier['native'] == native and len(carrier['events']) == 4,
                'both actual physical carriers changed and restored')
        for index, event in enumerate(carrier['events']):
            subject, up = index // 2, bool(index % 2)
            require((event['subject'], event['up']) == (subject, up) and
                    event['begin_monotonic_ns'] <= event['end_monotonic_ns'],
                    'ordered actual carrier operation receipts')
            if native:
                require(event['command'] == ['ip', 'link', 'set', f'peer{subject}', 'up' if up else 'down'] and
                        event['returncode'] == event['query_returncode'] == 0 and
                        event['stdout'] == event['stderr'] == event['query_stderr'] == '',
                        'successful actual native carrier command and raw readback')
                values = json.loads(event['query_stdout'])
                require(len(values) == 1 and 'UP' in values[0]['flags'] and
                        ('LOWER_UP' in values[0]['flags']) == up, 'actual native selected carrier state')
            else:
                require(event['qmp'] == dict(command='set_link', name=f'carrier{subject}', up=up, result={}),
                        'successful selected QEMU physical carrier command')
    return dict(passed=True, subject=lane, action=action, state='ready', probes=len(probes),
                controls=len(requests), native_clocks=clocks, original_timestamps_preserved=True,
                captured_prelude=[value['firmware'] for value in parsed],
                captures={f'lane{physical}.pcap': hashlib.sha256((path.parent / f'lane{physical}.pcap').read_bytes()).hexdigest()
                          for physical in range(2)}, full_F12_complete=False)

# SPDX-License-Identifier: GPL-3.0-or-later
"""Check pending DAD ownership and real packet timing across device transitions."""
import hashlib
import ipaddress
import json

from ipv6_device_frames import (ACTIONS, HELLO, BEGIN, ADDRESS, SUMMARY, ARM, CHANGE, LINK,
                                SECRET, END, FINISH, READY, STATE, CONFLICT, decode)
from ipv6_router_capture import require
from tcp_capture_clock import microseconds

STATES = ('probing', 'regenerating', 'retrying', 'exhausted')


def plan(action, state, early_ready=False):
    count = 4 if state == 'exhausted' else 1 if state == 'probing' else 2
    result = [(HELLO, 0), (BEGIN, 0), (STATE, 0), (ADDRESS, 10)]
    if state == 'exhausted':
        for attempt in range(4):
            if attempt:
                result.append((ADDRESS, 10 + attempt))
            result.append((CONFLICT, attempt))
    elif state != 'probing':
        result += [(CONFLICT, 0), (ADDRESS, 14)]
        if state == 'retrying':
            result.append((ADDRESS, 15))
    result += [(SECRET, 0), (LINK, 0)] + [(ADDRESS, 0)] * count + [(SUMMARY, 0), (ARM, 0)]
    if action == 'carrier':
        result.append((CHANGE, 0))
    result.append((LINK, 1))
    if early_ready and action == 'carrier' and state != 'exhausted':
        result.append((READY, 1))
    result += [(ADDRESS, 1)] * (count if action == 'carrier' else 0) + [(SUMMARY, 1)]
    if not early_ready and action == 'carrier' and state != 'exhausted':
        result.append((READY, 1))
    result += [(LINK, 2)] + [(ADDRESS, 2)] * (count if action == 'carrier' else 0)
    result += [(SUMMARY, 2), (ARM, 1)]
    if action == 'carrier':
        result.append((CHANGE, 1))
    result.append((LINK, 3))
    if action != 'carrier' or state != 'exhausted':
        result.append((READY, 3))
    result += [(SECRET, 4), (LINK, 4)] + [(ADDRESS, 4)] * (count if action == 'carrier' else 1)
    return result + [(SUMMARY, 4), (END, 0), (FINISH, 0)]


def _owner(value, flags):
    require(value['flags'] == flags and value['preferred'] == value['valid'] == 0xffffffff and
            ipaddress.IPv6Address(value['target']).is_link_local,
            'exact actual owner flags and lifetimes')


def _subject(physicals, subject, action, state):
    companion = physicals[1 - subject]
    requests = companion['requests']
    probes, conflicts = physicals[subject]['probes'], physicals[subject]['conflicts']

    def one(kind, stage):
        found = [value for value in requests if (value['kind'], value['stage']) == (kind, stage)]
        require(len(found) == 1, f'one query kind={kind} stage={stage}')
        return found[0]

    def moment(value):
        return microseconds(value['row'])

    def ack(value):
        return microseconds(companion['replies'][value['phase']])

    selector = one(STATE, 0)
    require((selector['flags'], selector['preferred'], selector['valid'], selector['target']) ==
            (STATES.index(state), 0, 0, bytes(16)), 'explicit captured pending state')
    count = 4 if state == 'exhausted' else 1 if state == 'probing' else 2
    initial_probes = {'probing': 1, 'regenerating': 1, 'retrying': 2, 'exhausted': 4}[state]
    require(len(probes) == initial_probes + int(action != 'carrier'),
            'exact initial and restored physical probe count')
    require(len(conflicts) == (0 if state == 'probing' else 4 if state == 'exhausted' else 1),
            'exact selected physical conflict count')
    require(all(value['nonce'] != bytes(6) for value in probes) and
            len({value['nonce'] for value in probes}) == len(probes),
            'fresh nonzero nonce for every actual DAD owner')
    old = one(ADDRESS, 10)
    _owner(old, 0x8c0)
    require(ack(one(BEGIN, 0)) <= moment(probes[0]) <= moment(old) and
            probes[0]['target'] == old['target'],
            'actual first probe precedes initial tentative query')
    failed = []
    for attempt, conflict in enumerate(conflicts):
        query, before = one(CONFLICT, attempt), one(ADDRESS, 10 + attempt)
        _owner(before, 0x8c0)
        _owner(query, 0x8c0)
        require(query['target'] == before['target'] == conflict['target'] == probes[attempt]['target'] and
                moment(before) <= moment(query) <= moment(conflict) <= ack(query),
                'selected tentative query NA and ACK causality')
        require(moment(probes[attempt]) <= moment(before),
                'actual selected probe before conflict query')
        failed.append(query['target'])
    require(len(set(failed)) == len(failed), 'fresh distinct conflict owners')
    current = old
    if state in ('regenerating', 'retrying'):
        current = one(ADDRESS, 14)
        _owner(current, 0x8c0)
        require(current['target'] not in failed and ack(one(CONFLICT, 0)) <= moment(current),
                'actual fresh tentative replacement')
        if state == 'retrying':
            retry = one(ADDRESS, 15)
            _owner(retry, 0x8c0)
            require(retry['target'] == current['target'] == probes[1]['target'] and
                    moment(current) <= moment(probes[1]) <= moment(retry),
                    'actual retry probe follows regeneration query')
    inventories = {}
    for stage in (0, 1, 2, 4):
        values = [value for value in requests if (value['kind'], value['stage']) == (ADDRESS, stage)]
        summary = one(SUMMARY, stage)
        expected_count = count if action == 'carrier' or stage == 0 else int(stage == 4)
        require(len(values) == expected_count and
                (summary['flags'], summary['preferred'], summary['valid'], summary['target']) ==
                (expected_count, int(bool(expected_count)), 0, bytes(16)),
                'complete address and connected route inventory')
        require(len({value['target'] for value in values}) == len(values),
                'unique actual address inventory')
        if action == 'carrier' or stage == 0:
            expected_targets = set(failed) | ({current['target']} if state != 'exhausted' else set())
            require({value['target'] for value in values} == expected_targets,
                    'exact retained failed and current owners')
            early_ready = (stage == 1 and state != 'exhausted' and
                           one(READY, 1)['phase'] < values[0]['phase'])
            for value in values:
                flags = 0x8c8 if value['target'] in failed else 0x880 if stage in (2, 4) or early_ready else 0x8c0
                _owner(value, flags)
        else:
            for value in values:
                _owner(value, 0x880)
        inventories[stage] = values
    for stage in (0, 1, 2, 3, 4):
        link = one(LINK, stage)
        down = stage in (1, 2)
        flags = 0x1002 if down and action == 'administrative' else 0x1003 if down and action == 'carrier' else 0x1043
        require((link['flags'], link['preferred'], link['valid'], link['target']) ==
                (flags, 1279 if down and action == 'mtu' else 1500,
                 int(not (down and action == 'mtu')), bytes(16)),
                'raw actual link flags MTU and IPv6 scope')
    for stage in (0, 4):
        secret = one(SECRET, stage)
        target = ipaddress.IPv6Address('fd00::100' if action == 'mtu' and stage == 4 else
                                      f'fd00::{10 + subject}').packed
        require((secret['flags'], secret['preferred'], secret['valid'], secret['target']) ==
                (0, 0, 0, target), 'actual stable secret scope lifetime')
    down, later, restored = one(SUMMARY, 1), one(LINK, 2), one(ARM, 1)
    require(moment(later) - ack(down) >= 4000000 and
            later['guest_ns'] - down['guest_ns'] >= 4000000000,
            'full original real four second unavailable interval')
    require(not any(ack(down) <= moment(value) <= moment(restored) for value in probes),
            'no physical probe during full unavailable interval')
    ready_delay, conflict_delay, restored_delay = None, None, None
    if action == 'carrier' and state != 'exhausted':
        ready = one(READY, 1)
        _owner(ready, 0x880)
        require(ready['target'] == current['target'] and
                ack(one(LINK, 1)) < moment(ready) < moment(later),
                'actual first ready query during carrier loss')
        if state == 'regenerating':
            require(all(value['target'] != ready['target'] for value in probes),
                    'replacement has no fabricated or observed probe during loss')
            conflict_delay = moment(ready) - moment(conflicts[0])
            require(2000000 <= conflict_delay <= 3100000,
                    f'regeneration NA to ready real bound: {conflict_delay}')
        else:
            matching = [value for value in probes if value['target'] == current['target']]
            require(len(matching) == 1, 'one actual pending probe clock')
            ready_delay = moment(ready) - moment(matching[0])
            require(1000000 <= ready_delay <= 2100000, f'pending real DAD bound: {ready_delay}')
    elif action != 'carrier':
        ready, fresh = one(READY, 3), inventories[4][0]
        _owner(ready, 0x880)
        require(ready['target'] == fresh['target'] == probes[-1]['target'] and
                (fresh['target'] != old['target']) == (action == 'mtu'),
                'actual restored scope identity')
        require(ack(restored) <= moment(probes[-1]) < moment(ready),
                'fresh actual probe after restoration')
        restored_delay = moment(ready) - moment(probes[-1])
        require(1000000 <= restored_delay <= 2100000,
                f'restored real DAD bound: {restored_delay}')
    if action != 'carrier' or state != 'exhausted':
        ready = one(READY, 3)
        _owner(ready, 0x880)
        require(ready['target'] == next(value['target'] for value in inventories[4]
                                        if value['flags'] == 0x880),
                'restored first ready query matches actual final owner')
        require(moment(one(LINK, 4)) - ack(ready) >= 4000000 and
                one(LINK, 4)['guest_ns'] - ready['guest_ns'] >= 4000000000,
                'full original real four second restored interval')
    else:
        require(moment(one(LINK, 4)) - ack(one(LINK, 3)) >= 4000000 and
                one(LINK, 4)['guest_ns'] - one(LINK, 3)['guest_ns'] >= 4000000000,
                'full exhausted restored quiet interval')
    return dict(subject=subject, actual_probe_count=len(probes), actual_conflict_count=len(conflicts),
                ready_after_probe_us=ready_delay, ready_after_conflict_us=conflict_delay,
                restored_after_probe_us=restored_delay,
                inventories={stage: [dict(flags=value['flags'], target=value['target'].hex())
                                     for value in values] for stage, values in inventories.items()})


def _carrier(path, native):
    carrier = json.loads(path.read_text())
    require(carrier['native'] == native and len(carrier['events']) == 4,
            'both original selected carriers changed and restored')
    for index, event in enumerate(carrier['events']):
        subject, up = index // 2, bool(index % 2)
        require((event['subject'], event['up']) == (subject, up) and
                event['begin_monotonic_ns'] <= event['end_monotonic_ns'],
                'ordered actual carrier receipts')
        if native:
            require(event['command'] == ['ip', 'link', 'set', f'peer{subject}', 'up' if up else 'down'] and
                    event['returncode'] == event['query_returncode'] == 0 and
                    event['stdout'] == event['stderr'] == event['query_stderr'] == '',
                    'successful original native carrier command')
            flags = json.loads(event['query_stdout'])
            require(len(flags) == 1 and 'UP' in flags[0]['flags'] and
                    ('LOWER_UP' in flags[0]['flags']) == up, 'actual native physical carrier readback')
        else:
            require(event['qmp'] == dict(command='set_link', name=f'carrier{subject}', up=up, result={}),
                    'actual successful selected QMP carrier command')


def inspect(path, lane, text, action, state, native=False, statistics=None, native_kernel_release=None):
    require(lane in (0, 1) and action in ACTIONS and state in STATES,
            'known pending device subject, action and state')
    require(not native or isinstance(native_kernel_release, str) and native_kernel_release,
            'actual native pending-device comparison kernel')
    plans = [plan(action, state)]
    if action == 'carrier' and state != 'exhausted':
        plans.append(plan(action, state, early_ready=True))
    physicals, clocks = decode(path, text, action, plans, native, statistics, allow_conflicts=True)
    observations = _subject(physicals, lane, action, state)
    if action == 'carrier':
        _carrier(path.parent / 'carrier.json', native)
    marker = f'IPV6_DEVICE_PASS adapters=2 action={action} state={state} quiet_seconds=4'
    require(text.splitlines().count(marker) == 1 and
            not any(value in text for value in ('IPV6_DEVICE_FAIL', 'PANIC:', 'FAULT pid=')),
            'one complete successful actual pending device client')
    return dict(passed=True, subject=lane, action=action, state=state, observations=observations,
                native_clocks=clocks, original_timestamps_preserved=True,
                captures={f'lane{physical}.pcap': hashlib.sha256(
                    (path.parent / f'lane{physical}.pcap').read_bytes()).hexdigest()
                    for physical in range(2)}, full_F12_complete=False)

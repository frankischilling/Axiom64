#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay the two observed legal overlaps and reject invented obligations."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_multicast.source_overlap import FIRST, valid


def captured(late_mode=False, between_calls=False):
    # Reduced from physical guest captures: stage two's old EXCLUDE retry
    # can precede BLOCK, and ALLOW can reach the wire before the next BLOCK.
    reports = {1: [(4, ())],
               2: [(4, ()), (6, (FIRST,)), (6, (FIRST,))] if late_mode else
                  [(4, (FIRST,)), (6, (FIRST,))],
               3: ([(5, (FIRST,))] if between_calls else []) + [(6, (FIRST,))] * 2,
               4: [(5, (FIRST + 1,))] * 2, 5: [(6, (FIRST + 1,))],
               6: [(5, (FIRST + 1,))] * 2, 7: [(3, ())] * 2}
    events = []
    packet = 0
    for stage, observed in reports.items():
        events.extend([('begin', stage), ('ready', stage)])
        early = (late_mode and stage == 2) or (between_calls and stage == 3)
        for index, report in enumerate(observed):
            if index == int(early):
                events.append(('applied', stage))
            events.append(('report', stage, packet, report))
            packet += 1
        events.append(('end', stage))
    return events


def main():
    for late, between in ((False, False), (True, False), (False, True), (True, True)):
        assert valid(captured(late, between)), (late, between)
    original = captured(True, True)
    for stage, kind in ((2, 4), (3, 6), (7, 3)):
        index = next(n for n, event in enumerate(original)
                     if event[:2] == ('report', stage) and event[3][0] == kind)
        changed = original[:index] + [('report', stage, 1000, original[index][3])] + original[index:]
        assert not valid(changed), ('extra copy', stage)
    index = next(n for n, event in enumerate(original) if event[:2] == ('report', 3))
    changed = original.copy()
    changed[index] = ('report', 3, changed[index][2], (5, (FIRST + 1,)))
    assert not valid(changed), 'wrong source before final BLOCK'
    changed = captured()
    indices = [n for n, event in enumerate(changed) if event[:2] == ('report', 2)]
    second = indices[1]
    changed[second] = ('report', 2, changed[indices[0]][2], changed[second][3])
    assert not valid(changed), 'one physical packet cannot discharge two source retransmissions'
    print('IPV4_SOURCE_OVERLAP_REPLAY_PASS legal=4 invalid=5')


if __name__ == '__main__':
    main()

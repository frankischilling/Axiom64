# SPDX-License-Identifier: GPL-3.0-or-later
"""Account for legal report/operation interleavings in the fixed overlap case."""
from dataclasses import dataclass, replace

FIRST = 0xc0000201
OPERATIONS = {1: ('join',), 2: ('block-a',), 3: ('allow-a', 'block-a'),
              4: ('block-b', 'allow-b'), 5: ('block-b',), 6: ('allow-b',), 7: ('leave',)}


@dataclass(frozen=True)
class State:
    include: bool = True
    blocked: int = 0
    mode: int = 0
    source: int = 0
    remaining: int = 0
    mode_key: int = 0
    source_key: int = 0
    operation: int = 0
    copied: tuple = ()
    packet: int = -1
    packet_obligations: frozenset = frozenset()


def changed(state, phase):
    operation = OPERATIONS[phase][state.operation]
    key = phase * 10 + state.operation
    fields = dict(operation=state.operation + 1)
    if operation in ('join', 'leave'):
        fields.update(include=operation == 'leave', blocked=0, mode=2, mode_key=-key)
    else:
        source = 1 if operation.endswith('-a') else 2
        blocked = state.blocked | source if operation.startswith('block-') else state.blocked & ~source
        fields.update(blocked=blocked, source=source, remaining=2, source_key=key)
    return replace(state, **fields)


def emitted(state):
    if state.mode:
        record = (3 if state.include else 4,
                  tuple(FIRST + n for n in range(2) if state.blocked & (1 << n)))
        obligations = (state.mode_key,) + ((state.source_key,) if state.remaining else ())
        return replace(state, mode=state.mode - 1, remaining=max(0, state.remaining - 1),
                       copied=state.copied + ((record, obligations),))
    if state.remaining:
        record = (6 if state.blocked & state.source else 5, (FIRST + (state.source == 2),))
        return replace(state, remaining=state.remaining - 1,
                       copied=state.copied + ((record, (state.source_key,)),))
    return None


def closure(states, phase, operations):
    # A report accepted before a socket change owns its old bytes until wire
    # completion. Enumerate those copies as well as calls between reports.
    result = set(states)
    pending = list(states)
    while pending:
        state = pending.pop()
        following = [emitted(state)]
        if operations and state.operation < len(OPERATIONS[phase]):
            following.append(changed(state, phase))
        for next_state in following:
            if next_state is not None and next_state not in result:
                result.add(next_state)
                pending.append(next_state)
    return result


def valid(events):
    """Every observed record must discharge real, distinct RV=2 obligations."""
    states = {State()}
    phase = 0
    operations = False
    for event in events:
        kind, value = event[:2]
        if kind == 'begin':
            phase = value
            operations = False
            states = {replace(state, operation=0) for state in states}
        elif kind == 'ready':
            operations = True
        elif kind == 'applied':
            states = {state for state in closure(states, phase, operations)
                      if state.operation == len(OPERATIONS[phase])}
            operations = False
        elif kind == 'end':
            if phase not in (1, 5):
                states = {state for state in states if not state.mode and not state.remaining and not state.copied}
        elif kind == 'report':
            packet, record = event[2:]
            following = set()
            for state in closure(states, phase, operations):
                if not state.copied or state.copied[0][0] != record:
                    continue
                obligations = state.copied[0][1]
                seen = state.packet_obligations if state.packet == packet else frozenset()
                # Two group records in one IP packet cannot satisfy two
                # retransmissions of the same mode or source obligation.
                if seen.intersection(obligations):
                    continue
                following.add(replace(state, copied=state.copied[1:], packet=packet,
                                      packet_obligations=seen.union(obligations)))
            states = following
        else:
            raise ValueError('known overlap capture event')
        if not states:
            return False
    return phase == 7 and any(state.include and not state.mode and not state.remaining and not state.copied
                              for state in states)

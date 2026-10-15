# SPDX-License-Identifier: GPL-3.0-or-later
"""Partition observed storage targets without losing logical phase coverage."""
import re


def partition_targets(targets, index=0, count=1):
    if type(index) is not int or type(count) is not int or count < 1 or not 0 <= index < count:
        raise ValueError('use a positive shard count and an index within that count')
    if not targets or count > len(targets):
        raise ValueError('every shard must contain an observed target')
    keys = []
    copied = []
    for target in targets:
        if set(target) != {'phase', 'operation', 'request'}:
            raise ValueError('a target requires exactly phase, operation and request')
        phase, operation, request = (target[name] for name in ('phase', 'operation', 'request'))
        if (not isinstance(phase, str) or not re.fullmatch(r'[a-z][a-z0-9-]*', phase) or
                operation not in ('write', 'flush') or type(request) is not int or request < 1):
            raise ValueError('invalid observed storage target')
        key = phase, operation
        if key in keys:
            raise ValueError('duplicate logical storage target')
        keys.append(key)
        copied.append(dict(phase=phase, operation=operation, request=request))
    selected = {key for position, key in enumerate(sorted(keys)) if position % count == index}
    return dict(shard_index=index, shard_count=count, all_targets=copied,
                selected_targets=[dict(target) for target in copied
                                  if (target['phase'], target['operation']) in selected])


def verify_complete_shards(selections):
    """Check one baseline group; callers must also verify each actual guest result."""
    if not selections:
        raise ValueError('no storage shards')
    first = selections[0]
    count = first['shard_count']
    seen = set()
    covered = set()
    expected = None
    for selection in selections:
        actual = partition_targets(selection['all_targets'], selection['shard_index'],
                                   selection['shard_count'])
        if actual != selection or selection['shard_count'] != count:
            raise ValueError('storage shard selection differs from its complete baseline')
        index = selection['shard_index']
        if index in seen:
            raise ValueError('duplicate storage shard')
        seen.add(index)
        keys = {(target['phase'], target['operation']) for target in selection['all_targets']}
        if expected is None:
            expected = keys
        if keys != expected:
            raise ValueError('storage baselines expose different logical targets')
        selected = {(target['phase'], target['operation'])
                    for target in selection['selected_targets']}
        if covered & selected:
            raise ValueError('storage shards overlap')
        covered |= selected
    if seen != set(range(count)) or covered != expected:
        raise ValueError('incomplete storage shard union')
    return dict(shards=count, logical_targets=len(expected), exact_partition=True)

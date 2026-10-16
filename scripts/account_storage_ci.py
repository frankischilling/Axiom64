# SPDX-License-Identifier: GPL-3.0-or-later
"""Emit complete storage matrices as single-line GitHub job outputs."""
import json


ROTATION_SHARDS = 4


def matrices():
    common = dict(provider=['build', 'runtime'], linkage=['static', 'dynamic'],
                  firmware=['bios', 'uefi'], transport=['modern', 'legacy'])
    return dict(account_clean_matrix=common,
                account_fault_matrix=dict(common, cache=['writeback', 'writethrough']),
                account_rotation_matrix=dict(common, scenario=['basic', 'expiry'],
                                             cache=['writeback', 'writethrough'],
                                             shard=list(range(ROTATION_SHARDS))))


def outputs():
    return [name + '=' + json.dumps(value, separators=(',', ':')) for name, value in matrices().items()] + [
        'rotation_shard_count=' + str(ROTATION_SHARDS)]


if __name__ == '__main__':
    print('\n'.join(outputs()))

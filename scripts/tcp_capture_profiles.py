# SPDX-License-Identifier: GPL-3.0-or-later
"""Require the complete native or guest cohort before auditing packet artifacts."""
import itertools


def require_complete_profiles(rows):
    reason = 'complete unique native or guest capture cohort'
    if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError(reason)
    native = all('client_namespace' in row for row in rows)
    keys = ('linkage',) if native else ('linkage', 'firmware', 'transport')
    expected = ({(value,) for value in ('native', 'static', 'dynamic')} if native else
                set(itertools.product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy'))))
    if (not native and any('client_namespace' in row for row in rows) or
            any(not isinstance(row.get(key), str) for row in rows for key in keys)):
        raise ValueError(reason)
    actual = [tuple(row[key] for key in keys) for row in rows]
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError(reason)

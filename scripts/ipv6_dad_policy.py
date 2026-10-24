# SPDX-License-Identifier: GPL-3.0-or-later
"""Pin the native prefix-cleanup change without learning expectations from test output."""
import re

PREFIX_CLEANUP_CHANGE = 'c7dc5b5228822d2389e6e441f10169e460bcc67a'


def retain_exhausted_prefix(release):
    """Linux through 6.18 retains the route; 6.19 and 7.0 clean it up.

    Both tag sources and actual 6.6/7.0 executions establish this boundary.
    A backport with different behavior must fail until its build is audited.
    """
    match = re.fullmatch(r'(\d+)\.(\d+)(?:[.\-+][A-Za-z0-9_.+\-]+)?', release) if isinstance(release, str) else None
    if not match:
        raise ValueError('explicit supported native Linux kernel release')
    version = tuple(map(int, match.groups()))
    if not (6, 6) <= version <= (7, 0):
        raise ValueError('native prefix-cleanup release needs a source audit')
    return version < (6, 19)

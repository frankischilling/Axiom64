# SPDX-License-Identifier: GPL-3.0-or-later
"""Name the compared kernel's IP option release contract."""
import re


def query_model(kernel):
    if kernel['system'] == 'Axiom64':
        return 'release'
    version = re.match(r'^(\d+)\.(\d+)(?:\D|$)', kernel['release'])
    if kernel['system'] != 'Linux' or version is None:
        raise ValueError('unknown IPv4 query kernel identity')
    return 'release' if tuple(map(int, version.groups())) < (6, 7) else 'read-only'

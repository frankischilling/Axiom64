# SPDX-License-Identifier: GPL-3.0-or-later
"""Recognize only exact, in-range free-counter findings from actual allocation maps."""
import hashlib
import re
import struct


def counter_findings(data, text):
    u16 = lambda offset: struct.unpack_from('<H', data, offset)[0]
    u32 = lambda offset: struct.unpack_from('<I', data, offset)[0]
    if len(data) < 2048 or u16(1080) != 0xef53 or u16(1082) != 0 or u32(1256):
        raise ValueError('not an eligible dirty classic volume')
    shift, revision = u32(1048), u32(1100)
    if shift > 2 or revision > 1:
        raise ValueError('unsupported classic geometry')
    size = 1024 << shift
    blocks, inodes, first = u32(1028), u32(1024), u32(1044)
    bpg, ipg = u32(1056), u32(1064)
    inode_size = u16(1112) if revision else 128
    first_inode = u32(1108) if revision else 11
    if (blocks * size != len(data) or first != int(size == 1024) or blocks <= first or
            not 0 < bpg <= size * 8 or not 0 < ipg <= size * 8 or
            inode_size not in (128, 256) or not 11 <= inodes <= len(data) // inode_size or
            first_inode != 11 or u32(1036) > blocks or u32(1040) > inodes):
        raise ValueError('counter geometry or stored totals are outside the volume')
    groups = (blocks - first + bpg - 1) // bpg
    if groups > 4096 or (inodes + ipg - 1) // ipg != groups:
        raise ValueError('inconsistent group geometry')
    expected = {}
    total_blocks = total_inodes = 0

    def free_bits(bitmap, count):
        if bitmap < first or bitmap >= blocks:
            raise ValueError('allocation map is outside the volume')
        start = bitmap * size
        return sum(not (data[start + number // 8] & (1 << (number % 8))) for number in range(count))

    for group in range(groups):
        offset = (first + 1) * size + group * 32
        if offset + 32 > len(data):
            raise ValueError('descriptor is outside the volume')
        block_count = min(bpg, blocks - first - group * bpg)
        inode_count = min(ipg, inodes - group * ipg)
        counted = (free_bits(u32(offset), block_count), free_bits(u32(offset + 4), inode_count))
        for kind, field, limit, actual in (('blocks', 12, block_count, counted[0]),
                                           ('inodes', 14, inode_count, counted[1])):
            stored = u16(offset + field)
            if stored > limit:
                raise ValueError('group counter is outside its allocation map')
            if stored != actual:
                expected[(kind, group)] = (stored, actual)
        total_blocks += counted[0]
        total_inodes += counted[1]
    for kind, offset, actual in (('blocks', 1036, total_blocks), ('inodes', 1040, total_inodes)):
        stored = u32(offset)
        if stored != actual:
            expected[(kind, None)] = (stored, actual)
    if not expected:
        raise ValueError('no actual free-counter drift')
    allowed = (r'^e2fsck \d.*$', r'^Pass [1-5]: .*$', r'^Fix\? no$',
               r'^.+: \*+ WARNING: Filesystem still has errors \*+$',
               r'^.+: \d+/\d+ files.*\d+/\d+ blocks$')
    pattern = (r'^Free (blocks|inodes) count wrong(?: for group #(\d+))? '
               r'\((\d+),\s*counted=(\d+)\)\.$')
    seen = set()
    for line in text.splitlines():
        finding = re.fullmatch(pattern, line)
        if finding:
            key = (finding[1], int(finding[2]) if finding[2] is not None else None)
            if key in seen or key not in expected or expected[key] != (int(finding[3]), int(finding[4])):
                raise ValueError('checker counter finding does not match the actual maps')
            seen.add(key)
        elif line and not any(re.fullmatch(item, line) for item in allowed):
            raise ValueError('additional filesystem damage: ' + line)
    if seen != set(expected):
        raise ValueError('checker omitted an actual counter discrepancy')
    return dict(classification='bounded-free-counters', groups=groups,
                counters=[dict(kind=kind, group=group, stored=values[0], counted=values[1])
                          for (kind, group), values in expected.items()],
                original_sha256=hashlib.sha256(data).hexdigest(), repair_performed=False)

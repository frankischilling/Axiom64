# SPDX-License-Identifier: GPL-3.0-or-later
"""Recognize only checker bitmap findings tied to allocated deletion-marked inodes."""
import hashlib
import re
import struct


def removed_numbers(line, limit):
    values = set()
    for word in line.split(':', 1)[1].split():
        match = re.fullmatch(r'-(?:(\d+)|\((\d+)--(\d+)\))', word)
        if not match:
            raise ValueError('the checker requests something other than freeing allocations')
        first = int(match[1] or match[2])
        last = int(match[1] or match[3])
        if first < 1 or last < first or last >= limit:
            raise ValueError('checker allocation range is outside the volume')
        for number in range(first, last + 1):
            if number in values:
                raise ValueError('duplicated checker allocation')
            values.add(number)
    return values


def deleted_allocation_findings(data, text):
    if len(data) < 2048 or struct.unpack_from('<H', data, 1080)[0] != 0xef53:
        raise ValueError('invalid classic ext2 volume')
    u32 = lambda offset: struct.unpack_from('<I', data, offset)[0]
    block_shift = u32(1048)
    if block_shift > 2:
        raise ValueError('unsupported classic block size')
    block_size = 1024 << block_shift
    blocks, inodes = u32(1028), u32(1024)
    first, blocks_per_group, inodes_per_group = u32(1044), u32(1056), u32(1064)
    inode_size = struct.unpack_from('<H', data, 1112)[0]
    first_inode = u32(1108)
    if (block_size not in (1024, 2048, 4096) or blocks * block_size != len(data) or
            not 0 < blocks_per_group <= block_size * 8 or
            not 0 < inodes_per_group <= block_size * 8 or inode_size not in (128, 256) or
            not 11 <= inodes <= len(data) // inode_size or
            first_inode != 11 or struct.unpack_from('<H', data, 1082)[0] != 0 or u32(1256)):
        raise ValueError('this is not an eligible dirty classic volume')
    allowed = (r'^e2fsck \d.*$', r'^Pass [1-5]: .*$','^Fix\\? no$',
               r'^Block bitmap differences:.*$', r'^Inode bitmap differences:.*$',
               r'^.+: \*+ WARNING: Filesystem still has errors \*+$',
               r'^.+: \d+/\d+ files.*\d+/\d+ blocks$')
    for line in text.splitlines():
        if line and not any(re.fullmatch(pattern, line) for pattern in allowed):
            raise ValueError('additional filesystem damage: ' + line)
    inode_lines = re.findall(r'^Inode bitmap differences:.*$', text, re.MULTILINE)
    block_lines = re.findall(r'^Block bitmap differences:.*$', text, re.MULTILINE)
    if len(inode_lines) != 1 or len(block_lines) > 1:
        raise ValueError('missing or duplicated allocation findings')
    expected_inodes = removed_numbers(inode_lines[0], inodes + 1)
    expected_blocks = removed_numbers(block_lines[0], blocks) if block_lines else set()
    if not expected_inodes:
        raise ValueError('no deletion-marked inode finding')
    descriptors = (first + 1) * block_size

    def allocated(number, inode=False):
        index = number - 1 if inode else number - first
        per_group = inodes_per_group if inode else blocks_per_group
        group, position = divmod(index, per_group)
        bitmap = u32(descriptors + group * 32 + (4 if inode else 0))
        offset = bitmap * block_size + position // 8
        if not 0 <= offset < len(data):
            raise ValueError('allocation bitmap is outside the volume')
        return bool(data[offset] & (1 << (position % 8)))

    owned = set()

    def claim(block, depth=0):
        if not block:
            return
        if block < first or block >= blocks or block in owned or not allocated(block):
            raise ValueError('unproven or overlapping retired allocation')
        owned.add(block)
        if depth:
            for index in range(block_size // 4):
                claim(u32(block * block_size + index * 4), depth - 1)

    for number in expected_inodes:
        if number < first_inode or not allocated(number, True):
            raise ValueError('reserved or unallocated retired inode')
        group, index = divmod(number - 1, inodes_per_group)
        table = u32(descriptors + group * 32 + 8)
        offset = table * block_size + index * inode_size
        if offset < 0 or offset + inode_size > len(data):
            raise ValueError('inode is outside the volume')
        mode, links = struct.unpack_from('<H', data, offset)[0], struct.unpack_from('<H', data, offset + 26)[0]
        if links or not u32(offset + 20) or mode & 0o170000 not in (0o100000, 0o040000, 0o120000, 0o140000):
            raise ValueError('inode lacks an unlinked deletion marker')
        if u32(offset + 32) or u32(offset + 112) or struct.unpack_from('<H', data, offset + 116)[0]:
            raise ValueError('unsupported retired inode layout')
        attribute = u32(offset + 104)
        fast = mode & 0o170000 == 0o120000 and u32(offset + 28) == (block_size // 512 if attribute else 0)
        if not fast:
            for slot in range(15):
                claim(u32(offset + 40 + slot * 4), 0 if slot < 12 else slot - 11)
        if attribute:
            if attribute < first or attribute >= blocks:
                raise ValueError('retired attribute is outside the volume')
            if u32(attribute * block_size) != 0xea020000 or u32(attribute * block_size + 4) != 1:
                raise ValueError('attribute ownership needs a separate checker finding')
            claim(attribute)
    if owned != expected_blocks:
        raise ValueError('checker bitmap changes do not match the retired inode allocations')
    return dict(inodes=sorted(expected_inodes), blocks=sorted(owned),
                original_sha256=hashlib.sha256(data).hexdigest(),
                classification='allocated-deletion-marked-inodes', repair_performed=False)

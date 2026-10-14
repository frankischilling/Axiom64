# SPDX-License-Identifier: GPL-3.0-or-later
"""Match refused checker findings to a singly named, deletion-marked file or symlink."""
import re
import struct

from ext2_recovery_inspection import deleted_allocation_findings


def named_retirement_findings(data, text):
    pattern = re.compile(r"Entry '([^'/]+)' in (/.*) \((\d+)\) has deleted/unused inode (\d+)\.  Clear\? no")
    retained, findings = [], []
    lines = text.splitlines()
    position = 0
    while position < len(lines):
        match = pattern.fullmatch(lines[position])
        if match:
            findings.append((match[1], match[2], int(match[3]), int(match[4])))
            position += 1
        else:
            retained.append(lines[position])
            position += 1
    if not findings or len(set(findings)) != len(findings):
        raise ValueError('missing or duplicated named-inode findings')
    result = deleted_allocation_findings(data, '\n'.join(retained) + '\n')
    u32 = lambda offset: struct.unpack_from('<I', data, offset)[0]
    u16 = lambda offset: struct.unpack_from('<H', data, offset)[0]
    block_size = 1024 << u32(1048)
    inodes, first, per_group = u32(1024), u32(1044), u32(1064)
    inode_size = u16(1112)
    descriptors = (first + 1) * block_size
    wanted = set(result['inodes'])
    directories, references = {}, {number: [] for number in wanted}
    for number in range(2, inodes + 1):
        group, index = divmod(number - 1, per_group)
        bitmap = u32(descriptors + group * 32 + 4)
        bitmap_byte = bitmap * block_size + index // 8
        if not 0 <= bitmap_byte < len(data):
            raise ValueError('inode bitmap outside the volume')
        if not data[bitmap_byte] & (1 << (index % 8)):
            continue
        table = u32(descriptors + group * 32 + 8)
        inode = table * block_size + index * inode_size
        if not 0 <= inode <= len(data) - inode_size:
            raise ValueError('inode outside the volume')
        if number in wanted and (u16(inode) & 0o170000 not in (0o100000, 0o120000) or
                                 u32(inode + 12) != u32(inode + 20)):
            raise ValueError('named retirement is not an eligible file with matching times')
        if u16(inode) & 0o170000 != 0o040000:
            continue
        if not u16(inode + 26) or u32(inode + 20):
            raise ValueError('a deleted directory needs a different recovery contract')
        length = u32(inode + 4)
        if not 0 < length <= 12 * block_size or length % block_size:
            raise ValueError('this observer requires bounded direct directory blocks')
        entries = {}
        for slot in range(length // block_size):
            block = u32(inode + 40 + 4 * slot)
            if not first <= block < len(data) // block_size:
                raise ValueError('directory block outside the volume')
            offset, end = block * block_size, (block + 1) * block_size
            while offset < end:
                target, extent, count = struct.unpack_from('<IHB', data, offset)
                if extent < 8 or extent % 4 or offset + extent > end or count > extent - 8:
                    raise ValueError('malformed directory record')
                if target:
                    name = bytes(data[offset + 8:offset + 8 + count]).decode('ascii')
                    if not name or '/' in name or '\0' in name or name in entries or target > inodes:
                        raise ValueError('malformed or duplicate directory name')
                    entries[name] = target
                    if target in wanted:
                        target_group, target_index = divmod(target - 1, per_group)
                        target_table = u32(descriptors + target_group * 32 + 8)
                        target_inode = target_table * block_size + target_index * inode_size
                        actual_type = data[offset + 7] if u32(1120) & 2 else 0
                        expected_type = {0o100000:1, 0o120000:7}.get(u16(target_inode) & 0o170000)
                        if actual_type and actual_type != expected_type:
                            raise ValueError('named retirement has an inconsistent directory type')
                        references[target].append((number, name))
                offset += extent
        if entries.get('.') != number or '..' not in entries:
            raise ValueError('missing directory ancestry')
        directories[number] = entries
    if 2 not in directories:
        raise ValueError('missing root directory')
    paths, pending = {2: '/'}, [2]
    while pending:
        parent = pending.pop()
        for name, target in directories[parent].items():
            if name in ('.', '..') or target not in directories:
                continue
            if target in paths or directories[target]['..'] != parent:
                raise ValueError('ambiguous directory ancestry')
            paths[target] = paths[parent].rstrip('/') + '/' + name
            pending.append(target)
    if set(paths) != set(directories):
        raise ValueError('unreachable directory')
    expected = set()
    for number, names in references.items():
        if len(names) != 1:
            raise ValueError('retirement does not retain exactly one namespace reference')
        parent, name = names[0]
        expected.add((name, paths[parent], parent, number))
    if set(findings) != expected:
        raise ValueError('checker names do not match the actual directory records')
    result.update(classification='singly-named-deletion-marked-files-or-symlinks',
                  restored_names=[dict(name=name, directory=path, parent=parent, inode=number)
                                  for name, path, parent, number in sorted(expected)])
    return result

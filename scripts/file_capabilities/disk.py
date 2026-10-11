# SPDX-License-Identifier: GPL-3.0-or-later
"""Inspect persistent metadata using e2fsprogs and an independent disk reader."""
import re
import struct
from file_capabilities.common import debugfs, digest, fsck


def inode_offset(data, number):
    block = 1024 << struct.unpack_from('<I', data, 1048)[0]
    group, index = divmod(number - 1, struct.unpack_from('<I', data, 1064)[0])
    first = struct.unpack_from('<I', data, 1044)[0]
    revision = struct.unpack_from('<I', data, 1100)[0]
    size = struct.unpack_from('<H', data, 1112)[0] if revision else 128
    table = struct.unpack_from('<I', data, (first + 1) * block + 32 * group + 8)[0]
    return table * block + size * index


def attributes(data, offset, allow_inline=False):
    """Read EA entries without calling the kernel codec or trusting guest lists."""
    block = 1024 << struct.unpack_from('<I', data, 1048)[0]
    number = struct.unpack_from('<I', data, offset + 104)[0]
    inline = None
    inode_size = struct.unpack_from('<H', data, 1112)[0]
    if allow_inline and inode_size > 128:
        extra = struct.unpack_from('<H', data, offset + 128)[0]
        start = offset + 128 + extra
        if extra <= inode_size - 132 and struct.unpack_from('<I', data, start)[0] == 0xea020000:
            inline = data[start:offset + inode_size]
    if not number and inline is None:
        return {}, None
    if number:
        raw = data[number * block:(number + 1) * block]
    else:
        # Inode-body value offsets are relative to the first entry. Normalize
        # only for the independent native reader; the guest rejects this layout.
        raw = bytearray(block)
        struct.pack_into('<3I', raw, 0, 0xea020000, 1, 1)
        raw[32:32 + len(inline) - 4] = inline[4:]
        at = 32
        while raw[at:at + 4] != bytes(4):
            value, size = struct.unpack_from('<H', raw, at + 2)[0], struct.unpack_from('<I', raw, at + 8)[0]
            if size:
                struct.pack_into('<H', raw, at + 2, value + 32)
            at += (16 + raw[at] + 3) & ~3
            if at > 32 + len(inline) - 4:
                raise ValueError('invalid native inline EA entry bounds')
    raw = bytes(raw)
    magic, references, count, _ = struct.unpack_from('<4I', raw)
    if magic != 0xea020000 or count != 1 or references < 1 or any(raw[16:32]):
        raise ValueError('invalid EA header in independent disk reader')
    names, ranges, at, order = {}, [], 32, None
    while raw[at:at + 4] != bytes(4):
        length, index, value, external, size, _ = struct.unpack_from('<BBHIII', raw, at)
        suffix = raw[at + 16:at + 16 + length]
        key = (index, length, suffix)
        if not index or external or (number and order is not None and key <= order):
            raise ValueError('invalid EA name order or external value')
        order = key
        if size and (value % 4 or value + ((size + 3) & ~3) > block):
            raise ValueError('invalid EA value bounds')
        if (index, suffix) in names:
            raise ValueError('duplicate EA name')
        names[index, suffix] = raw[value:value + size]
        if size:
            ranges.append((value, value + ((size + 3) & ~3)))
        at += (16 + length + 3) & ~3
        if at > block - 4:
            raise ValueError('unterminated EA entry list')
    ranges.sort()
    if ranges and (ranges[0][0] < at + 4 or any(a[1] > b[0] for a, b in zip(ranges, ranges[1:]))):
        raise ValueError('overlapping EA values')
    header = dict(block=number or None, references=references, bytes=raw, layout='external' if number else 'inline')
    if number and inline is not None:
        copied = bytearray(data)
        struct.pack_into('<I', copied, offset + 104, 0)
        inside, _ = attributes(copied, offset, allow_inline=True)
        if names.keys() & inside.keys():
            raise ValueError('duplicate native inline/external EA')
        names.update(inside)
        header['layout'] = 'mixed'
    return names, header


def verify_persist(disk, output, label, linkage, native=False):
    record = fsck(disk, output, label)
    expected = {'user.binary': bytes((0, 255, 17, 0, 127)), 'user.empty': b'',
                'trusted.private': b'secret', 'security.custom': b'metadata',
                'security.capability': struct.pack('<5I', 0x02000001, 2, 0, 1 << 8, 0)}
    path = '/filecap-persisted/renamed'
    stat = debugfs(disk, 'stat ' + path, output / (label + '-inode.log'))
    alias = debugfs(disk, 'stat /filecap-persisted/alias', output / (label + '-alias.log'))
    number = int(re.search(r'Inode:\s+(\d+)', stat)[1])
    if not re.search(r'Inode:\s+' + str(number) + r'\b', alias) or 'Links: 2' not in stat:
        raise ValueError('independent hardlink inode differs')
    if not re.search(r'User:\s+65537\s+Group:\s+131073', stat) or 'Mode:  0755' not in stat:
        raise ValueError('independent full-width ownership differs')
    for name, value in expected.items():
        target = output / (label + '-' + name + '.ea')
        debugfs(disk, f'ea_get -f "{target}" {path} {name}', output / (target.name + '.log'))
        if target.read_bytes() != value:
            raise ValueError('independently exported attribute differs: ' + name)
    target = output / (label + '-helper.elf')
    debugfs(disk, f'dump {path} "{target}"', output / (label + '-dump.log'))
    client = output / 'inputs/build' / ('file-capabilities-' + linkage)
    if target.read_bytes() != client.read_bytes():
        raise ValueError('persistent executable differs from the tested client')
    data = disk.read_bytes()
    attrs, header = attributes(data, inode_offset(data, number), allow_inline=native)
    raw_expected = {(1, b'binary'): expected['user.binary'], (1, b'empty'): b'',
                    (4, b'private'): b'secret', (6, b'custom'): b'metadata',
                    (6, b'capability'): expected['security.capability']}
    if attrs != raw_expected or header['references'] != 1:
        raise ValueError('raw on-disk attribute map/reference count differs')
    (output / (label + '-ea-block.bin')).write_bytes(header.pop('bytes'))
    revision, features = struct.unpack_from('<I', data, 1100)[0], struct.unpack_from('<I', data, 1116)[0]
    if revision != 1 or not features & 8:
        raise ValueError('persisted EA volume lacks the dynamic ext2 format')
    return dict(fsck=record, inode=number, revision=revision, compatible_features=features,
                disk=disk.name, disk_sha256=digest(disk), executable_sha256=digest(target),
                attributes={name: digest(output / (label + '-' + name + '.ea')) for name in expected}, **header)

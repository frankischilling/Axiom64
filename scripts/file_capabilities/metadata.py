# SPDX-License-Identifier: GPL-3.0-or-later
"""Boot real shared EAs, malformed disks, legacy capability words and I/O faults."""
import argparse
from pathlib import Path
import re
import shutil
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from file_capabilities.common import boot, debugfs, digest, fsck, image, prepare, save, snapshot, volume
from file_capabilities.disk import attributes, inode_offset

WIRE = (
    ('wire-v1', struct.pack('<3I', 0x01000001, 2, 0), 22, 0, '2', '2', '1', 'restricted'),
    ('wire-v2', struct.pack('<5I', 0x02000001, 2, 0, 0, 0), 0, 0, '2', '2', '1', 'restricted'),
    ('wire-v3-root0', struct.pack('<6I', 0x03000001, 2, 0, 0, 0, 0), 0, 0, '2', '2', '1', 'restricted'),
    ('wire-v3-foreign', struct.pack('<6I', 0x03000001, 2, 0, 0, 0, 1000), 0, 0, '0', '0', '0', 'normal'),
    ('wire-root-overflow', struct.pack('<6I', 0x03000001, 2, 0, 0, 0, 0xffffffff), 75, 0, '0', '0', '0', 'normal'),
    ('wire-unused-flags', struct.pack('<5I', 0x02000003, 2, 0, 0, 0), 22, 0, '2', '2', '1', 'restricted'),
    ('wire-version4', struct.pack('<5I', 0x04000001, 2, 0, 0, 0), 22, 22, '0', '0', '0', 'normal'),
    ('wire-truncated', struct.pack('<5I', 0x02000001, 2, 0, 0, 0)[:-1], 22, 22, '0', '0', '0', 'normal'),
    ('wire-empty', b'', 22, 22, '0', '0', '0', 'normal'),
)


def number(disk, name):
    return int(re.search(r'Inode:\s+(\d+)', debugfs(disk, 'stat /' + name))[1])


def seeded(output, linkage, block=1024, inode=128, prefix='shared'):
    disk = output / f'seed-{prefix}-{linkage}-{block}-{inode}.img'
    if disk.exists():
        raise ValueError('seed evidence already exists: ' + str(disk))
    volume(disk, block, inode)
    client = ROOT / 'build' / ('file-capabilities-' + linkage)
    cap = output / 'seed-capability.bin'
    cap.write_bytes(struct.pack('<5I', 0x02000001, 2, 0, 0, 0))
    control = output / 'control.bin'
    control.write_bytes(b'unrelated ordinary file bytes\0\xff\n')
    for name in ('alpha', 'beta'):
        debugfs(disk, f'write "{client}" /{name}', write=True)
        debugfs(disk, f'sif /{name} mode 0100755', write=True)
        if inode > 128:
            # Linux ext2 stores EAs in external blocks. Reserve the complete
            # extra inode area so debugfs cannot choose ext4's inline layout.
            debugfs(disk, f'sif /{name} extra_isize {inode - 128}', write=True)
    debugfs(disk, f'write "{control}" /control', write=True)
    debugfs(disk, 'ea_set /alpha user.shared original', write=True)
    debugfs(disk, 'ea_set /alpha user.é utf8', write=True)
    debugfs(disk, f'ea_set -f "{cap}" /alpha security.capability', write=True)
    debugfs(disk, 'ea_set /alpha security.opaque-extra invisible', write=True)
    data = bytearray(disk.read_bytes())
    alpha, beta = inode_offset(data, number(disk, 'alpha')), inode_offset(data, number(disk, 'beta'))
    attribute = struct.unpack_from('<I', data, alpha + 104)[0]
    struct.pack_into('<I', data, beta + 104, attribute)
    struct.pack_into('<I', data, beta + 28, struct.unpack_from('<I', data, beta + 28)[0] + block // 512)
    struct.pack_into('<I', data, attribute * block + 4, 2)
    at = attribute * block + 32
    while data[at:at + 4] != bytes(4):
        length = data[at]
        if data[at + 16:at + 16 + length] == b'opaque-extra':
            data[at + 1] = 9
        at += (16 + length + 3) & ~3
    disk.write_bytes(data)
    fsck(disk, output, disk.stem + '-seed')
    return disk


def host_value(disk, output, label, path, name, expected):
    export = output / (label + '-' + name + '.ea')
    debugfs(disk, f'ea_get -f "{export}" {path} {name}', output / (export.name + '.log'))
    if export.read_bytes() != expected:
        raise ValueError('host attribute export differs: ' + name)


def shared(output, linkage, firmware, transport, block, inode):
    seed = seeded(output, linkage, block, inode)
    label = f'shared-{linkage}-{block}-{inode}-{firmware}-{transport}'
    disk = output / (label + '.img')
    shutil.copy2(seed, disk)
    script = ('/bin/busybox mount -t ext2 /dev/vda /tmp\n/bin/file-capabilities-tests --shared-contract\n'
              '/bin/busybox sync\n/bin/busybox umount /tmp\n')
    iso = image(output, label, linkage, script)
    receipt = boot(output, label, iso, disk, firmware, transport)
    check = fsck(disk, output, label)
    host_value(disk, output, label, '/beta', 'user.shared', b'changed')
    host_value(disk, output, label, '/beta', 'user.é', b'utf8')
    data = disk.read_bytes()
    values, header = attributes(data, inode_offset(data, number(disk, 'beta')))
    if values != {(1, b'shared'): b'changed', (1, 'é'.encode()): b'utf8', (9, b'opaque-extra'): b'invisible'}:
        raise ValueError('copy-on-write lost opaque metadata or retained a stripped mark')
    if header['references'] != 1:
        raise ValueError('private copy-on-write block reference count differs')
    exported = output / (label + '-beta.elf')
    debugfs(disk, f'dump /beta "{exported}"')
    if exported.read_bytes() != (ROOT / 'build' / ('file-capabilities-' + linkage)).read_bytes():
        raise ValueError('copy-on-write changed file data')
    control = output / (label + '-control.bin')
    debugfs(disk, f'dump /control "{control}"')
    if control.read_bytes() != (output / 'control.bin').read_bytes():
        raise ValueError('copy-on-write changed unrelated data')
    if 'alpha' in debugfs(disk, 'ls -p /') or 'renamed' in debugfs(disk, 'ls -p /'):
        raise ValueError('unlinked inode retained a live directory entry')
    return dict(kind='shared', boot=receipt, fsck=check, disk=disk.name, disk_sha256=digest(disk),
                private_block=header['block'], references=header['references'])


def malformed(output, linkage):
    base = seeded(output, linkage, prefix='rejected')
    raw = base.read_bytes()
    alpha = inode_offset(raw, number(base, 'alpha'))
    ea = struct.unpack_from('<I', raw, alpha + 104)[0] * 1024
    entry = ea + 32
    second = entry + ((16 + raw[entry] + 3) & ~3)
    variants = []
    def change(name, offset, fmt, value, error=117):
        data = bytearray(raw)
        struct.pack_into(fmt, data, offset, value)
        target = output / ('malformed-' + linkage + '-' + name + '.img')
        target.write_bytes(data)
        variants.append((name, target, error))
    for name, offset, fmt, value in (
        ('magic', ea, '<I', 0), ('zero-refcount', ea + 4, '<I', 0),
        ('excess-refcount', ea + 4, '<I', 1025), ('missing-reference', ea + 4, '<I', 3),
        ('too-few-references', ea + 4, '<I', 1), ('multiple-blocks', ea + 8, '<I', 2),
        ('reserved-header', ea + 16, '<I', 1), ('external-value', entry + 4, '<I', 1),
        ('zero-namespace', entry + 1, '<B', 0), ('empty-user-name', entry, '<B', 0),
        ('embedded-nul', entry + 16, '<B', 0), ('bad-sort', entry + 1, '<B', 7),
        ('unaligned-value', entry + 2, '<H', 1023), ('value-in-names', entry + 2, '<H', 32),
        ('long-value', entry + 8, '<I', 1025), ('overlapping-value', second + 2, '<H',
            struct.unpack_from('<H', raw, entry + 2)[0]),
        ('entry-hash', entry + 12, '<I', 1), ('block-hash', ea + 12, '<I', 1),
        ('outside-device', alpha + 104, '<I', len(raw) // 1024),
        ('metadata-pointer', alpha + 104, '<I', 2), ('sector-count', alpha + 28, '<I', 0),
        ('data-alias', alpha + 40, '<I', ea // 1024), ('missing-feature', 1116, '<I',
            struct.unpack_from('<I', raw, 1116)[0] & ~8)):
        change(name, offset, fmt, value)
    # ACL bytes may be well formed but their DAC policy remains unsupported.
    data = bytearray(raw)
    data[entry + 1], data[second + 1] = 2, 6
    target = output / ('malformed-' + linkage + '-acl-policy.img')
    target.write_bytes(data)
    variants.append(('acl-policy', target, 95))
    data = bytearray(raw)
    free = len(raw) // 1024 - 1
    data[free * 1024:(free + 1) * 1024] = raw[ea:ea + 1024]
    struct.pack_into('<I', data, alpha + 104, free)
    target = output / ('malformed-' + linkage + '-unallocated-pointer.img')
    target.write_bytes(data)
    variants.append(('unallocated-pointer', target, 117))
    inline = output / ('malformed-' + linkage + '-inline-layout.img')
    volume(inline, inode=256)
    client = ROOT / 'build' / ('file-capabilities-' + linkage)
    debugfs(inline, f'write "{client}" /inline', write=True)
    debugfs(inline, 'ea_set /inline user.inline ext4-layout', write=True)
    fsck(inline, output, inline.stem + '-seed')
    variants.append(('inline-layout', inline, 95))
    return variants


def rejected(output, linkage, firmware, transport):
    variants = malformed(output, linkage)
    rows = []
    for first in range(0, len(variants), 8):
        group = variants[first:first + 8]
        label = f'rejected-{linkage}-{firmware}-{transport}-{first // 8}'
        before = {path.name: digest(path) for _, path, _ in group}
        script = ''.join(f'/bin/file-capabilities-tests --reject-mount /dev/vd{chr(97 + i)} {error}\n'
                         for i, (_, _, error) in enumerate(group))
        iso = image(output, label, linkage, script)
        receipt = boot(output, label, iso, [path for _, path, _ in group], firmware, transport)
        after = {path.name: digest(path) for _, path, _ in group}
        if before != after:
            raise ValueError('rejected ext2 volume was modified')
        rows.append(dict(kind='rejected', boot=receipt, before=before, after=after,
                         cases=[dict(name=name, disk=path.name, errno=error) for name, path, error in group]))
    return rows


def wire(output, linkage, firmware, transport):
    label = f'wire-{linkage}-{firmware}-{transport}'
    disk = output / (label + '.img')
    volume(disk)
    client = ROOT / 'build' / ('file-capabilities-' + linkage)
    protected = output / 'protected.bin'
    protected.write_bytes(b'original')
    debugfs(disk, f'write "{protected}" /protected', write=True)
    debugfs(disk, 'sif /protected mode 0100000', write=True)
    script = '/bin/busybox mount -t ext2 /dev/vda /tmp\n'
    for name, value, get_error, exec_error, permitted, effective, secure, dump in WIRE:
        debugfs(disk, f'write "{client}" /{name}', write=True)
        debugfs(disk, f'sif /{name} mode 0100755', write=True)
        cap = output / (name + '.bin')
        cap.write_bytes(value)
        debugfs(disk, f'ea_set -f "{cap}" /{name} security.capability', write=True)
        length = 24 if name == 'wire-v3-foreign' else 20
        script += f'/bin/file-capabilities-tests --disk-wire {name} {length} {get_error} {exec_error} {permitted} {effective} {secure} {dump}\n'
    fsck(disk, output, label + '-before')
    shutil.copy2(disk, output / (label + '-before.img'))
    script += '/bin/busybox umount /tmp\n'
    iso = image(output, label, linkage, script)
    receipt = boot(output, label, iso, disk, firmware, transport)
    return dict(kind='wire', boot=receipt, disk=disk.name, disk_sha256=digest(disk), fsck=fsck(disk, output, label))


def failure(output, linkage, firmware, transport, kind):
    label = f'{kind}-{linkage}-{firmware}-{transport}'
    disk = output / (label + '.img')
    volume(disk, capacity=8 * 1024 * 1024)
    source = output / 'fault.bin'
    source.write_bytes(b'unchanged file payload\n')
    debugfs(disk, f'write "{source}" /fault', write=True)
    debugfs(disk, 'ea_set /fault user.value original', write=True)
    debugfs(disk, 'ea_set /fault user.unrelated preserved', write=True)
    cap = output / (label + '-capability.bin')
    cap.write_bytes(struct.pack('<5I', 0x02000001, 2, 0, 0, 0))
    debugfs(disk, f'ea_set -f "{cap}" /fault security.capability', write=True)
    rules = None
    if kind != 'full':
        rules = output / (label + '.conf')
        if kind == 'write-error':
            block = int(re.search(r'File ACL:\s+(\d+)', debugfs(disk, 'stat /fault'))[1])
            text = ('[inject-error]\nevent = "write_aio"\niotype = "write"\n'
                    f'sector = "{block * 2}"\nerrno = "5"\nonce = "on"\n')
        else:
            text = ('[set-state]\nevent = "flush_to_disk"\nstate = "1"\nnew_state = "2"\n\n'
                    '[inject-error]\nevent = "flush_to_disk"\nstate = "2"\niotype = "flush"\n'
                    'errno = "5"\nonce = "on"\n')
        rules.write_text(text)
    shutil.copy2(disk, output / (label + '-before.img'))
    script = ('/bin/busybox mount -t ext2 /dev/vda /tmp\n/bin/file-capabilities-tests --' +
              ('full-contract' if kind == 'full' else 'fault-contract') +
              '\n/bin/busybox sync\n/bin/busybox umount /tmp\n')
    iso = image(output, label, linkage, script)
    receipt = boot(output, label, iso, disk, firmware, transport, rules)
    check = fsck(disk, output, label)
    host_value(disk, output, label, '/fault', 'user.value', b'original' if kind == 'full' else b'recovered')
    host_value(disk, output, label, '/fault', 'user.unrelated', b'preserved')
    host_value(disk, output, label, '/fault', 'security.capability', cap.read_bytes())
    exported = output / (label + '-payload.bin')
    debugfs(disk, f'dump /fault "{exported}"')
    if exported.read_bytes() != source.read_bytes():
        raise ValueError('failed metadata operation changed file payload')
    return dict(kind=kind, boot=receipt, fsck=check, disk=disk.name, disk_sha256=digest(disk))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/file-capabilities/metadata')
    parser.add_argument('--firmware', choices=('bios', 'uefi'), default='bios')
    parser.add_argument('--transport', choices=('modern', 'legacy'), default='modern')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--case', choices=('all', 'shared', 'rejected', 'wire', 'failure'), default='all')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    prepare()
    snapshot(output)
    rows = []
    for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
        if args.case in ('all', 'shared'):
            for block, inode in ((1024, 128), (2048, 256), (4096, 256)):
                rows.append(shared(output, linkage, args.firmware, args.transport, block, inode))
                save(output / 'results.json', rows)
        if args.case in ('all', 'rejected'):
            rows += rejected(output, linkage, args.firmware, args.transport)
            save(output / 'results.json', rows)
        if args.case in ('all', 'wire'):
            rows.append(wire(output, linkage, args.firmware, args.transport))
            save(output / 'results.json', rows)
        if args.case in ('all', 'failure'):
            for kind in ('write-error', 'flush-error', 'full'):
                rows.append(failure(output, linkage, args.firmware, args.transport, kind))
                save(output / 'results.json', rows)


if __name__ == '__main__':
    main()

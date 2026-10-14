# SPDX-License-Identifier: GPL-3.0-or-later
"""Recover an actual deleted-open inode without changing named files or weakening checks."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

from ext2_inspection import disk_files
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args
from ext2_test import FORMATS, create_volume, debugfs, inode_offset
from fetch import ROOT
from fixture_archive import archive_fixture

CLIENT = 'userspace/tests/fs/ext2-deleted-recovery.c'
INPUT = 'scripts/tests/fixtures/ext2-deleted-open-inode.raw.gz'
RAW_SHA256 = 'd26bbe2752604ea777f829c422f35891f4ef5226fd21d8cf7b23a7e62a35e944'


def build(directory):
    program = directory / 'ext2-deleted-recovery'
    command = [*compiler_args('build'), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-static', str(ROOT / CLIENT), '-o', str(program)]
    subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    return program, dict(command=command, binary_sha256=digest(program))


def boot(directory, image, disk, firmware, transport, mode, expected):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', 'if=none,id=recovery,format=raw,file=' + str(disk),
               '-device', 'virtio-blk-pci,drive=recovery,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    started = time.monotonic_ns()
    log = directory / 'guest.log'
    timed_out = False
    with log.open('xb') as stream:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.STDOUT, cwd=ROOT)
        try:
            process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text().replace('\r\n', '\n')
    marker = ('EXT2_DELETED_RECOVERY_DENIED mode=' + mode + ' errno=' + str(expected) if expected
              else 'EXT2_DELETED_RECOVERY_PASS mode=' + mode + ' mounted=1 clean_unmount=1')
    passed = (not timed_out and process.returncode == 1 and text.splitlines().count(marker) == 1 and
              text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text and
              'Firmware: ' + firmware.upper() in text and
              not any(word in text for word in ('EXT2_DELETED_RECOVERY_FAIL', 'PANIC:', 'FAULT pid=')))
    return dict(passed=passed, command=command, returncode=process.returncode, timed_out=timed_out,
                elapsed_ns=time.monotonic_ns() - started, log_sha256=digest(log))


def directory_entries(raw, number):
    size = 1024 << struct.unpack_from('<I', raw, 1024 + 24)[0]
    inode = inode_offset(raw, number)
    length = struct.unpack_from('<I', raw, inode + 4)[0]
    assert 0 < length <= 12 * size and length % size == 0
    for slot in range(length // size):
        block = struct.unpack_from('<I', raw, inode + 40 + slot * 4)[0]
        assert block
        offset, end = block * size, (block + 1) * size
        while offset < end:
            target, extent, count = struct.unpack_from('<IHB', raw, offset)
            assert extent >= 8 and extent % 4 == 0 and offset + extent <= end
            yield offset, target, bytes(raw[offset + 8:offset + 8 + count])
            offset += extent


def lookup(raw, path):
    number = 2
    for name in path.split('/'):
        matches = [target for unused, target, entry in directory_entries(raw, number)
                   if target and entry == name.encode()]
        assert len(matches) == 1
        number, = matches
    return number


def removed_directory(raw):
    data = bytearray(raw)
    matches = [(offset, target) for offset, target, name in directory_entries(raw, 2)
               if name == b'lost+found']
    assert len(matches) == 1
    entry, number = matches[0]
    for unused, target, name in directory_entries(raw, number):
        assert not target or name in (b'.', b'..')
    struct.pack_into('<I', data, entry, 0)
    inode = inode_offset(data, number)
    struct.pack_into('<H', data, inode + 26, 0)
    struct.pack_into('<I', data, inode + 20, 17)
    parent = inode_offset(data, 2)
    links = struct.unpack_from('<H', data, parent + 26)[0]
    struct.pack_into('<H', data, parent + 26, links - 1)
    return data, number


def generated_deleted(directory, block_size, inode_size, features, count=1):
    disk = directory / ('generated-' + str(block_size) + '-' + features + '-' + str(count) + '.raw')
    create_volume(disk, block_size, inode_size, features)
    for path in ('/rotation', '/rotation/records'):
        debugfs(disk, 'mkdir ' + path, True)
    payload = directory / 'generated-journal.bin'
    payload.write_bytes(b'A46Lgenerated named data\n')
    debugfs(disk, 'write ' + str(payload) + ' /rotation/records/journal', True)
    length = (12 + block_size // 4 + 3) * block_size + 713 if count == 1 else block_size + 37
    payload.write_bytes(b'x' * length)
    for number in range(count):
        debugfs(disk, 'write ' + str(payload) + ' /retired-' + str(number), True)
    data = bytearray(disk.read_bytes())
    retired = [(position, number) for position, number, name in directory_entries(data, 2)
               if number and name.startswith(b'retired-')]
    assert len(retired) == count
    for entry, number in retired:
        inode = inode_offset(data, number)
        struct.pack_into('<I', data, entry, 0)
        struct.pack_into('<H', data, inode + 26, 0)
        struct.pack_into('<I', data, inode + 20, 17)
    struct.pack_into('<H', data, 1024 + 58, 0)
    return bytes(data)


def cases(raw, directory):
    yield 'actual-deleted-open', raw, 'checked', 0
    yield 'default-rejected', raw, 'default', 117
    yield 'readonly-rejected', raw, 'checked-ro', 117
    offset = inode_offset(raw, 17)
    assert struct.unpack_from('<H', raw, offset + 26)[0] == 0
    assert struct.unpack_from('<I', raw, offset + 20)[0] != 0
    data = bytearray(raw)
    struct.pack_into('<I', data, offset + 20, 0)
    yield 'unproven-zero-link', bytes(data), 'checked', 117
    data = bytearray(raw)
    struct.pack_into('<H', data, offset + 26, 1)
    yield 'deleted-linked-inode', bytes(data), 'checked', 117
    data = bytearray(raw)
    struct.pack_into('<H', data, 1024 + 58, 1)
    yield 'clean-deleted-inode', bytes(data), 'checked', 117
    data = bytearray(raw)
    struct.pack_into('<I', data, offset + 32, 0x10)
    yield 'unsupported-deleted-flags', bytes(data), 'checked', 95
    current = lookup(raw, 'rotation/records/journal')
    live = inode_offset(raw, current)
    data = bytearray(raw)
    struct.pack_into('<I', data, offset + 40, struct.unpack_from('<I', raw, live + 40)[0])
    yield 'deleted-data-overlaps-live', bytes(data), 'checked', 117
    data = bytearray(raw)
    parent = lookup(raw, 'rotation/records')
    entry, = [position for position, target, name in directory_entries(raw, parent)
              if name == b'journal']
    struct.pack_into('<I', data, entry, 17)
    yield 'deleted-inode-still-named', bytes(data), 'checked', 117
    data, removed = removed_directory(raw)
    yield 'deleted-empty-directory', bytes(data), 'checked', 0
    changed = bytearray(data)
    available, = [position for position, target, name in directory_entries(data, removed)
                  if not target][:1]
    struct.pack_into('<I', changed, available, current)
    changed[available + 6:available + 8] = bytes((7, 1))
    changed[available + 8:available + 15] = b'foreign'
    yield 'deleted-directory-with-data', bytes(changed), 'checked', 117
    changed = bytearray(data)
    up, = [position for position, target, name in directory_entries(data, removed) if name == b'..']
    struct.pack_into('<I', changed, up, removed)
    yield 'deleted-directory-parent-cycle', bytes(changed), 'checked', 117
    data = bytearray(raw)
    struct.pack_into('<H', data, offset, 0o120777)
    for slot in range(4):
        block = struct.unpack_from('<I', data, offset + 40 + slot * 4)[0]
        amount = min(1024, 3584 - slot * 1024)
        data[block * 1024:block * 1024 + amount] = b'x' * amount
    yield 'deleted-block-symlink', bytes(data), 'checked', 0
    attribute_disk = directory / 'shared-attribute-input.raw'
    attribute_disk.write_bytes(raw)
    debugfs(attribute_disk, 'ea_set /rotation/records/journal user.kept preserved-value', True)
    data = bytearray(attribute_disk.read_bytes())
    attribute = struct.unpack_from('<I', data, live + 104)[0]
    assert attribute and struct.unpack_from('<I', data, attribute * 1024)[0] == 0xea020000
    assert struct.unpack_from('<I', data, attribute * 1024 + 4)[0] == 1
    struct.pack_into('<I', data, attribute * 1024 + 4, 2)
    struct.pack_into('<I', data, offset + 104, attribute)
    sectors = struct.unpack_from('<I', data, offset + 28)[0]
    struct.pack_into('<I', data, offset + 28, sectors + 2)
    yield 'deleted-shared-attribute', bytes(data), 'checked', 0
    struct.pack_into('<I', data, attribute * 1024 + 4, 3)
    yield 'deleted-attribute-wrong-reference-count', bytes(data), 'checked', 117
    for block_size, inode_size, features in FORMATS[1:]:
        yield ('deleted-layout-' + str(block_size) + '-' + str(inode_size) + '-' + features,
               generated_deleted(directory, block_size, inode_size, features), 'checked', 0)
    yield 'seventy-deleted-inodes', generated_deleted(directory, 1024, 128, 'default', 70), 'checked', 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to((ROOT / 'build').resolve()):
        raise ValueError('use a fresh owned directory under build/')
    directory.mkdir(parents=True, exist_ok=False)
    names = [CLIENT, INPUT, 'scripts/ext2_deleted_inode_test.py', 'scripts/account_store_guest.py',
             'scripts/ext2_test.py', 'scripts/fixture_archive.py', 'scripts/build_musl.py',
             'scripts/image.py', 'Makefile', 'dependencies.json', 'sources.lock.json', 'ports.lock.json',
             'boot/limine.conf', 'vendor/limine.h', 'userspace/init/main.c', 'userspace/init/console.c',
             'userspace/init/console.h', 'userspace/init/seed_records.h', 'scripts/build_busybox.py']
    names += [Path(module.__file__).resolve().relative_to(ROOT).as_posix()
              for module in list(sys.modules.values()) if getattr(module, '__file__', None)
              and Path(module.__file__).resolve().is_relative_to(ROOT / 'scripts')]
    names += [path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
              if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm')]
    source = {name: digest(ROOT / name) for name in names}
    (directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    for name in source:
        copy = directory / 'source' / name
        copy.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, copy)
    raw = gzip.decompress((ROOT / INPUT).read_bytes())
    assert len(raw) == 16 * 1024 * 1024 and hashlib.sha256(raw).hexdigest() == RAW_SHA256
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
    rows = []
    for name, data, mode, expected in cases(raw, directory):
        cell = directory / name
        cell.mkdir()
        image = fixture(cell, 'build', 'static', program_builder=lambda *unused: build(cell),
                        filename='ext2-deleted-recovery-' + name,
                        command='/bin/ext2-deleted-recovery-' + name + ' ' + mode + ' ' + str(expected))
        for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
            for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                phase = cell / (firmware + '-' + transport)
                phase.mkdir()
                disk = phase / 'disk.raw'
                disk.write_bytes(data)
                before_files, before_metadata, before_directories = disk_files(disk, metadata=True)
                row = boot(phase, image, disk, firmware, transport, mode, expected)
                row.update(case=name, firmware=firmware, transport=transport, expected_errno=expected,
                           before_sha256=hashlib.sha256(data).hexdigest(), after_sha256=digest(disk),
                           before_named_files={name: dict(bytes=len(contents), sha256=hashlib.sha256(contents).hexdigest())
                                               for name, contents in before_files.items()},
                           before_metadata=before_metadata, before_directories=before_directories)
                rows.append(row)
                try:
                    if not row['passed']:
                        raise RuntimeError('deleted inode recovery failed: ' + name + '/' + firmware + '/' + transport)
                    if expected:
                        assert disk.read_bytes() == data, 'rejected volume changed'
                    else:
                        after_files, after_metadata, after_directories = disk_files(disk, metadata=True)
                        row.update(after_named_files={name: dict(bytes=len(contents), sha256=hashlib.sha256(contents).hexdigest())
                                                     for name, contents in after_files.items()},
                                   after_metadata=after_metadata, after_directories=after_directories)
                        assert after_files == before_files and after_metadata == before_metadata
                        assert after_directories == before_directories
                        if name == 'deleted-shared-attribute':
                            current = lookup(data, 'rotation/records/journal')
                            inode = inode_offset(data, current)
                            attribute = struct.unpack_from('<I', data, inode + 104)[0]
                            after = disk.read_bytes()
                            assert struct.unpack_from('<I', after, inode + 104)[0] == attribute
                            assert struct.unpack_from('<I', after, attribute * 1024 + 4)[0] == 1
                            before_block = bytearray(data[attribute * 1024:(attribute + 1) * 1024])
                            after_block = bytearray(after[attribute * 1024:(attribute + 1) * 1024])
                            before_block[4:8] = after_block[4:8] = bytes(4)
                            assert before_block == after_block
                            assert 'preserved-value' in debugfs(disk, 'ea_list /rotation/records/journal')
                            row['shared_attribute_value_and_owner_preserved'] = True
                        fsck = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True, timeout=60)
                        (phase / 'fsck.log').write_bytes(fsck.stdout + fsck.stderr)
                        row['fsck_returncode'] = fsck.returncode
                        assert fsck.returncode == 0, 'guest recovery did not produce a clean independent filesystem'
                        row['named_files_and_metadata_unchanged'] = True
                    row['retained_disk'] = archive_fixture(disk, remove=True)
                except BaseException as error:
                    row.update(passed=False, host_error=repr(error))
                    if disk.exists() and not disk.with_name('disk.raw.gz').exists():
                        row['retained_failed_disk'] = archive_fixture(disk, remove=False)
                    (directory / 'acceptance.json').write_text(json.dumps(dict(
                        passed=False, terminal=True, cells=len(rows), error=repr(error)), indent=2) + '\n')
                    raise
                finally:
                    (directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                print('EXT2_DELETED_RECOVERY_CELL_PASS ' + name + '/' + firmware + '/' + transport, flush=True)
    stable = source == {name: digest(ROOT / name) for name in source}
    (directory / 'acceptance.json').write_text(json.dumps(dict(
        passed=stable and bool(rows) and all(row['passed'] for row in rows),
        source_stable=stable, cells=len(rows),
        matrix_complete=args.firmware == args.transport == 'both',
        unchanged_denials=sum(bool(row['expected_errno']) and row['before_sha256'] == row['after_sha256'] for row in rows),
        strict_post_recovery_checks=sum(row.get('fsck_returncode') == 0 for row in rows),
        host_repair_performed=False), indent=2) + '\n')
    assert stable, 'source changed during deleted-inode validation'
    print('EXT2_DELETED_RECOVERY_MATRIX_PASS cells=' + str(len(rows)), flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Recover real open-unlinked inodes after VM termination, then reject damaged variants."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

from fetch import ROOT
from account_store_guest import fixture
from account_store_test import environment
from build_musl import compiler_args
from ext2_test import debugfs, inode_offset
from fixture_archive import archive_fixture

LAYOUTS = {'1024': (1024, 128, True), '2048': (2048, 256, True),
           '4096': (4096, 256, True), '1024-untyped': (1024, 128, False)}
CLIENT = 'userspace/tests/fs/ext2-journal-lifetime.c'
CONTROLS = ('unmarked', 'positive-links', 'named', 'counter', 'unallocated',
            'flags', 'orphan-list', 'orphan-list-readonly', 'clean', 'hardware-readonly')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def strict(disk, log):
    result = subprocess.run(['e2fsck', '-f', '-n', str(disk)], capture_output=True, text=True)
    log.write_text(result.stdout + result.stderr)
    assert result.returncode == 0, log
    assert not re.search(r'count wrong|Fix\?|Clear\?|still has errors', result.stdout + result.stderr, re.I), log


def template(directory, label):
    size, inode_size, typed = LAYOUTS[label]
    directory.mkdir()
    disk = directory / 'initial.raw'
    with disk.open('xb') as stream:
        stream.truncate(64 * 1024 * 1024)
    command = ['mke2fs', '-q', '-F', '-t', 'ext3', '-b', str(size), '-I', str(inode_size)]
    if not typed:
        command += ['-O', '^filetype']
    result = subprocess.run([*command, str(disk)], capture_output=True, text=True)
    (directory / 'mke2fs.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0
    seed = directory / 'seed.bin'
    seed.write_bytes(bytes((index * 31 + 17) & 255 for index in range(9 * size - 128)))
    debugfs(disk, 'write ' + str(seed) + ' /seed', write=True)
    strict(disk, directory / 'initial-fsck.log')
    raw = disk.read_bytes()
    record = dict(command=[*command, str(disk)], block_size=size, inode_size=inode_size,
                  archive=archive_fixture(disk, remove=True))
    save(directory / 'template.json', record)
    return raw


def counts(text, phase):
    rows = re.findall(r'^JOURNAL_LIFETIME_COUNTS phase=' + phase +
                      r' blocks=(\d+) inodes=(\d+) block_size=(\d+)$', text, re.M)
    assert len(rows) == 1, (phase, text[-2000:])
    return tuple(map(int, rows[0]))


def armed_records(text):
    return re.findall(r'^JOURNAL_LIFETIME_ARMED file=(\d+) symlink=(\d+) directory=(\d+)\r?\n', text, re.M)


def boot(image, disk, directory, firmware, transport, cache, mode):
    directory.mkdir()
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', 'if=none,id=lifetime,format=raw,cache=' + cache + ',file=' + str(disk) +
               (',readonly=on' if mode == 'reject-hardware' else ''), '-device',
               'virtio-blk-pci,drive=lifetime,' + ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    started, killed, timed_out = time.monotonic(), False, False
    log = directory / 'guest.log'
    with log.open('xb') as stream:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=stream, stderr=subprocess.STDOUT)
        try:
            if mode == 'hold':
                deadline = started + 90
                while time.monotonic() < deadline:
                    text = log.read_text(errors='replace')
                    if armed_records(text):
                        assert process.poll() is None
                        process.kill()
                        assert process.wait(timeout=10) == -9
                        killed = True
                        break
                    assert process.poll() is None, text[-2000:]
                    time.sleep(.02)
                else:
                    timed_out = True
                    raise AssertionError('open-unlink boundary exceeded unchanged90s limit')
            else:
                try:
                    process.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    raise
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    text = log.read_text().replace('\r\n', '\n')
    row = dict(command=command, returncode=process.returncode, elapsed_seconds=time.monotonic() - started,
               timed_out=timed_out, actual_vm_sigkill=killed, log_sha256=digest(log), mode=mode)
    save(directory / 'boot.json', row)
    assert 'Firmware: ' + firmware.upper() in text
    assert not any(value in text for value in ('PANIC:', 'FAULT pid=', 'JOURNAL_LIFETIME_FAIL')), text[-2000:]
    if mode == 'hold':
        assert killed and process.returncode == -9
    else:
        marker = 'JOURNAL_LIFETIME_REJECT_PASS' if mode.startswith('reject-') else 'JOURNAL_LIFETIME_PASS mode=' + mode
        assert process.returncode == 1 and not timed_out, (directory, text[-2000:])
        assert text.splitlines().count(marker) == text.splitlines().count('AXIOM64_TESTS_PASS') == 1
        assert 'AXIOM64_EXIT status=0' in text
    return row, text


def retired(raw, text):
    matches = armed_records(text)
    assert len(matches) == 1
    numbers = tuple(map(int, matches[0]))
    assert len(set(numbers)) == 3
    for number, kind in zip(numbers, (0o100000, 0o120000, 0o040000)):
        inode = inode_offset(raw, number)
        assert struct.unpack_from('<H', raw, inode)[0] & 0o170000 == kind
        assert struct.unpack_from('<H', raw, inode + 26)[0] == 0
        assert struct.unpack_from('<I', raw, inode + 20)[0] != 0
    inode = inode_offset(raw, numbers[0])
    assert struct.unpack_from('<I', raw, inode + 88)[0] and struct.unpack_from('<I', raw, inode + 104)[0]
    journal = inode_offset(raw, 8)
    first = struct.unpack_from('<I', raw, journal + 40)[0]
    size = 1024 << struct.unpack_from('<I', raw, 1048)[0]
    assert struct.unpack_from('>I', raw, first * size)[0] == 0xc03b3998
    assert struct.unpack_from('>I', raw, first * size + 28)[0] == 0
    return numbers


def damaged(original, numbers, name, disk):
    raw = bytearray(original)
    inode = inode_offset(raw, numbers[0])
    u32 = lambda offset: struct.unpack_from('<I', raw, offset)[0]
    size = 1024 << u32(1048)
    if name == 'unmarked':
        struct.pack_into('<I', raw, inode + 20, 0)
    elif name == 'positive-links':
        struct.pack_into('<H', raw, inode + 26, 1)
    elif name == 'counter':
        struct.pack_into('<I', raw, 1036, u32(1036) + 1)
    elif name == 'unallocated':
        block = u32(inode + 40)
        group, bit = divmod(block - u32(1044), u32(1056))
        descriptor = (u32(1044) + 1) * size + group * 32
        bitmap = u32(descriptor)
        assert raw[bitmap * size + bit // 8] & (1 << (bit % 8))
        raw[bitmap * size + bit // 8] &= ~(1 << (bit % 8))
        struct.pack_into('<H', raw, descriptor + 12, struct.unpack_from('<H', raw, descriptor + 12)[0] + 1)
        struct.pack_into('<I', raw, 1036, u32(1036) + 1)
    elif name == 'flags':
        struct.pack_into('<I', raw, inode + 32, 0x80000)
    elif name.startswith('orphan-list'):
        struct.pack_into('<I', raw, 1256, numbers[0])
    elif name == 'clean':
        struct.pack_into('<H', raw, 1082, 1)
    disk.write_bytes(raw)
    if name == 'named':
        debugfs(disk, 'ln <' + str(numbers[0]) + '> /resurrect', write=True)
        assert re.search(r'Inode:\s+' + str(numbers[0]) + r'\b', debugfs(disk, 'stat /resurrect'))
        raw = bytearray(disk.read_bytes())
        struct.pack_into('<H', raw, inode + 26, 0)
        disk.write_bytes(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ext2-journal-lifetime')
    parser.add_argument('--provider', choices=('build', 'runtime', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--cache', choices=('writethrough', 'writeback', 'both'), default='both')
    parser.add_argument('--layout', choices=(*LAYOUTS, 'all'), default='all')
    args = parser.parse_args()
    output = args.directory.resolve()
    assert output.is_relative_to((ROOT / 'build').resolve()) and re.fullmatch(r'[a-zA-Z0-9-]{1,70}', output.name)
    output.mkdir(exist_ok=False)
    select = lambda name, values: values if getattr(args, name) in ('both', 'all') else (getattr(args, name),)
    grid = list(itertools.product(select('provider', ('build', 'runtime')), select('linkage', ('static', 'dynamic')),
                select('firmware', ('bios', 'uefi')), select('transport', ('modern', 'legacy')),
                select('cache', ('writethrough', 'writeback')), select('layout', tuple(LAYOUTS))))
    names = [CLIENT, 'scripts/ext2_journal_lifetime_test.py', 'Makefile', 'dependencies.json', 'ports.lock.json',
             'sources.lock.json', 'vendor/limine.h', 'boot/limine.conf']
    names += [path.relative_to(ROOT).as_posix() for base in ('kernel', 'userspace/init') for path in (ROOT / base).rglob('*')
              if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm', '.c', '.h')]
    names += [Path(module.__file__).resolve().relative_to(ROOT).as_posix() for module in list(sys.modules.values())
              if getattr(module, '__file__', None) and Path(module.__file__).resolve().is_relative_to(ROOT / 'scripts')]
    sources = {name: digest(ROOT / name) for name in names}
    save(output / 'source-inputs.json', sources)
    for name in sources:
        target = output / 'source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    images, binaries = {}, {}

    def image(provider, linkage, mode):
        key = (provider, linkage, mode)
        if key in images:
            return images[key]
        directory = output / '-'.join(key)
        directory.mkdir()

        def build(provider, linkage, directory):
            key = provider, linkage
            if key not in binaries:
                binary = directory / 'client'
                command = [*compiler_args(provider), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                           *(['-static'] if linkage == 'static' else []), str(ROOT / CLIENT), '-o', str(binary)]
                subprocess.run(command, cwd=ROOT, env=environment(), check=True)
                headers = subprocess.check_output(['readelf', '-W', '-l', str(binary)], text=True)
                dynamic = subprocess.check_output(['readelf', '-W', '-d', str(binary)], text=True)
                if linkage == 'static':
                    assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
                else:
                    assert '/lib/ld-musl-x86_64.so.1' in headers and '(NEEDED)' in dynamic
                    assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
                binaries[key] = binary, dict(command=command, headers=headers, dynamic=dynamic, binary_sha256=digest(binary))
            return binaries[key]

        filename = 'journal-lifetime-' + output.name + '-' + mode
        images[key] = fixture(directory, provider, linkage, program_builder=build,
                              filename=filename, command='/bin/' + filename + ' ' + mode)
        return images[key]

    rows, controls, error = [], [], None
    try:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
        templates = {}
        for label in select('layout', tuple(LAYOUTS)):
            templates[label] = template(output / ('template-' + label), label)
        for provider, linkage, firmware, transport, cache, label in grid:
            case = output / '-'.join((provider, linkage, firmware, transport, cache, label))
            case.mkdir()
            row = dict(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                       cache=cache, layout=label, passed=False, boots={})
            rows.append(row)
            with tempfile.TemporaryDirectory(prefix='axiom64-journal-lifetime-') as temporary:
                disk = Path(temporary) / 'disk.raw'
                disk.write_bytes(templates[label])
                try:
                    held, text = boot(image(provider, linkage, 'hold'), disk, case / 'hold', firmware, transport, cache, 'hold')
                    row['boots']['hold'] = held
                    original = disk.read_bytes()
                    numbers = retired(original, text)
                    baseline = counts(text, 'baseline')
                    retained = case / 'interrupted.raw'
                    retained.write_bytes(original)
                    row.update(retired_inodes=numbers, baseline_counts=baseline,
                               interrupted=archive_fixture(retained, remove=True))
                    for mode in ('verify', 'readonly'):
                        disk.write_bytes(original)
                        result, text = boot(image(provider, linkage, mode), disk, case / mode, firmware, transport, cache, mode)
                        assert counts(text, 'recovered') == baseline
                        if mode == 'verify':
                            assert counts(text, 'after-allocation') == baseline
                        strict(disk, case / mode / 'fsck.log')
                        seed = case / mode / 'seed.bin'
                        debugfs(disk, 'dump /seed ' + str(seed))
                        size = LAYOUTS[label][0]
                        assert seed.read_bytes() == bytes((index * 31 + 17) & 255 for index in range(9 * size - 128))
                        retained = case / (mode + '.raw')
                        shutil.copyfile(disk, retained)
                        result['disk'] = archive_fixture(retained, remove=True)
                        row['boots'][mode] = result
                    row['passed'] = True
                    save(output / 'results.json', rows)
                    print('JOURNAL_LIFETIME_CELL_PASS ' + '/'.join((provider, linkage, firmware, transport, cache, label)), flush=True)
                    if provider == 'build' and linkage == 'static' and cache == 'writethrough':
                        for name in CONTROLS:
                            damaged(original, numbers, name, disk)
                            before = digest(disk)
                            mode = 'reject-unsupported' if name == 'flags' else 'reject-hardware' if name == 'hardware-readonly' else \
                                   'reject-readonly' if name == 'orphan-list-readonly' else 'reject-damaged'
                            directory = case / name
                            result, _ = boot(image(provider, linkage, mode), disk, directory, firmware, transport, cache, mode)
                            assert digest(disk) == before
                            retained = directory / 'disk.raw'
                            shutil.copyfile(disk, retained)
                            controls.append(dict(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                                cache=cache, layout=label, case=name, passed=True, before_raw_sha256=before,
                                boot=result, disk=archive_fixture(retained, remove=True)))
                            save(output / 'controls.json', controls)
                except BaseException:
                    retained = case / 'failed.raw'
                    shutil.copyfile(disk, retained)
                    archive_fixture(retained, remove=True)
                    raise
    except BaseException as failure:
        error = repr(failure)
        raise
    finally:
        stable = sources == {name: digest(ROOT / name) for name in sources}
        expected_controls = sum(provider == 'build' and linkage == 'static' and cache == 'writethrough'
                                for provider, linkage, firmware, transport, cache, label in grid) * len(CONTROLS)
        save(output / 'results.json', rows)
        save(output / 'controls.json', controls)
        save(output / 'receipt.json', dict(passed=error is None and stable and len(rows) == len(grid) and
            all(row['passed'] for row in rows) and len(controls) == expected_controls,
            terminal=True, source_stable=stable, error=error, cells=len(rows), expected_cells=len(grid),
            controls=len(controls), expected_controls=expected_controls, actual_vm_sigkills=sum(
            row['boots'].get('hold', {}).get('actual_vm_sigkill', False) for row in rows),
            timeout_seconds=90, host_repair_performed=False,
            matrix_complete=all(getattr(args, name) == 'both' for name in ('provider', 'linkage', 'firmware', 'transport', 'cache'))
            and args.layout == 'all', selection=vars(args) | {'directory': str(output)}))


if __name__ == '__main__':
    main()

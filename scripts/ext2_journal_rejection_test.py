#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject unsupported and inconsistent journals without writing their volumes."""
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

from fetch import ROOT
from account_store_guest import fixture
from account_store_test import environment
from build_musl import compiler_args
from ext2_test import inode_offset
from fixture_archive import archive_fixture


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def variants(native):
    source = native / '1024'
    original = gzip.decompress((source / 'crashed.raw.gz').read_bytes())
    mapping = list(struct.unpack('<' + 'I' * ((source / 'journal-map.bin').stat().st_size // 4),
                                 (source / 'journal-map.bin').read_bytes()))
    transaction = (source / 'transaction.bin').read_bytes()
    count = struct.unpack_from('<I', transaction)[0]
    targets = [struct.unpack_from('<I', transaction, 4 + index * 1028)[0]
               for index in range(count)]
    assert count == 6 and len(set(targets)) == count
    assert struct.unpack_from('>II', original, mapping[1] * 1024) == (0xc03b3998, 1)
    first_tag = mapping[1] * 1024 + 12
    for index, label in enumerate(('checksum', '64-bit', 'uuid', 'journal-target',
                                   'geometry', 'journal-inode', 'allocation', 'external')):
        raw = bytearray(original)
        if index in (0, 1):
            struct.pack_into('>I', raw, mapping[0] * 1024 + (36 if index == 0 else 40),
                             1 if index == 0 else 3)
        elif index == 2:
            raw[mapping[0] * 1024 + 48] ^= 1
        elif index == 3:
            struct.pack_into('>I', raw, first_tag, mapping[1])
        elif index == 4:
            payload = mapping[2 + targets.index(1)] * 1024
            struct.pack_into('<I', raw, payload + 4, 0)
        elif index == 5:
            inode = inode_offset(raw, 8)
            struct.pack_into('>I', raw, first_tag, inode // 1024)
            payload = mapping[2] * 1024
            raw[payload:payload + 1024] = raw[inode // 1024 * 1024:(inode // 1024 + 1) * 1024]
            raw[payload + inode % 1024] ^= 1
        elif index == 6:
            # The third journal entry is the old tail; the fourth is newly allocated.
            block = targets[3]
            bitmap = struct.unpack_from('<I', raw, 2048)[0]
            assert bitmap == targets[1] and block < 8193
            payload = mapping[2 + targets.index(bitmap)] * 1024
            bit = block - 1
            assert raw[payload + bit // 8] & (1 << (bit % 8))
            raw[payload + bit // 8] &= ~(1 << (bit % 8))
        else:
            struct.pack_into('<I', raw, 1024 + 228, 1)
        yield label, bytes(raw)


def build(provider, linkage, directory):
    program = directory / 'journal-reject'
    command = [*compiler_args(provider), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               *(['-static'] if linkage == 'static' else []),
               str(ROOT / 'userspace/tests/fs/ext2-journal-reject.c'), '-o', str(program)]
    subprocess.run(command, cwd=ROOT, env=environment(), check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    dynamic = subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True)
    if linkage == 'static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert '/lib/ld-musl-x86_64.so.1' in headers and '(NEEDED)' in dynamic
        assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    return program, dict(command=command, binary_sha256=digest(program), headers=headers, dynamic=dynamic)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ext2-journal-rejection')
    parser.add_argument('--native-directory', type=Path, default=ROOT / 'build/ext2-journal-native')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--provider', choices=('build', 'runtime', 'both'), default='both')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    args = parser.parse_args()
    output, native = args.directory.resolve(), args.native_directory.resolve()
    assert all(path.is_relative_to((ROOT / 'build').resolve()) for path in (output, native))
    producer = json.loads((native / 'receipt.json').read_text())
    assert producer['passed'] and producer['terminal'] and producer['source_stable']
    assert all(digest(ROOT / name) == expected for name, expected in producer['source_inputs'].items())
    output.mkdir(exist_ok=False)
    names = ['scripts/ext2_journal_rejection_test.py', 'userspace/tests/fs/ext2-journal-reject.c']
    names += [path.relative_to(ROOT).as_posix() for base in ('kernel', 'userspace/init')
              for path in (ROOT / base).rglob('*')
              if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm', '.c', '.h')]
    names += [Path(module.__file__).resolve().relative_to(ROOT).as_posix()
              for module in list(sys.modules.values()) if getattr(module, '__file__', None)
              and Path(module.__file__).resolve().is_relative_to(ROOT / 'scripts')]
    names += ['Makefile', 'dependencies.json', 'ports.lock.json', 'sources.lock.json',
              'vendor/limine.h', 'boot/limine.conf']
    sources = {name: digest(ROOT / name) for name in names}
    (output / 'source-inputs.json').write_text(json.dumps(sources, indent=2) + '\n')
    for name in sources:
        destination = output / 'source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    rows, error = [], None
    try:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       cwd=ROOT, check=True)
        for provider in ('build', 'runtime') if args.provider == 'both' else (args.provider,):
            for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
                for mode in ('invalid', 'hardware'):
                    case = output / (provider + '-' + linkage + '-' + mode)
                    case.mkdir()
                    filename = 'ext2-journal-reject-' + mode
                    image = fixture(case, provider, linkage, program_builder=build, filename=filename,
                                    command='/bin/' + filename + ' ' + mode)
                    for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                        for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                            phase = case / (firmware + '-' + transport)
                            phase.mkdir()
                            inputs = (variants(native) if mode == 'invalid' else
                                      [('readonly', gzip.decompress((native / '1024/crashed.raw.gz').read_bytes()))])
                            disks = []
                            for label, raw in inputs:
                                disk = phase / (label + '.raw')
                                disk.write_bytes(raw)
                                disks.append((label, disk, digest(disk)))
                            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                                       '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                                       '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                            for index, (_, disk, _) in enumerate(disks):
                                command += ['-drive', 'if=none,id=d' + str(index) + ',format=raw,file=' + str(disk) +
                                            (',readonly=on' if mode == 'hardware' else ''), '-device',
                                            'virtio-blk-pci,drive=d' + str(index) + ',' +
                                            ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
                            if firmware == 'uefi':
                                variables = phase / 'VARS.fd'
                                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                            '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                            started, timed_out = time.monotonic(), False
                            log = phase / 'guest.log'
                            with log.open('xb') as stream:
                                process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                                           stdout=stream, stderr=subprocess.STDOUT)
                                try:
                                    process.wait(timeout=90)
                                except subprocess.TimeoutExpired:
                                    timed_out = True
                                    process.kill()
                                    process.wait()
                            row = dict(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                                       mode=mode, command=command, returncode=process.returncode,
                                       timed_out=timed_out, elapsed_seconds=time.monotonic() - started,
                                       log_sha256=digest(log), passed=False)
                            rows.append(row)
                            text = log.read_text().replace('\r\n', '\n')
                            assert not timed_out and process.returncode == 1
                            marker = 'EXT2_JOURNAL_REJECT_PASS mode=' + mode + ' volumes=' + str(len(disks))
                            assert text.splitlines().count(marker) == text.splitlines().count('AXIOM64_TESTS_PASS') == 1
                            assert 'AXIOM64_EXIT status=0' in text and 'Firmware: ' + firmware.upper() in text
                            assert not any(value in text for value in ('PANIC:', 'FAULT pid=', 'EXT2_JOURNAL_REJECT_FAIL'))
                            assert all(digest(disk) == expected for _, disk, expected in disks)
                            row.update(passed=True, unchanged_volumes=len(disks), disks={})
                            for label, disk, expected in disks:
                                row['disks'][label] = dict(input_raw_sha256=expected,
                                    retained=archive_fixture(disk, remove=True))
                            (output / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                            print('EXT2_JOURNAL_REJECTION_CELL_PASS ' + '/'.join((provider, linkage, mode, firmware, transport)), flush=True)
    except BaseException as failure:
        error = repr(failure)
        raise
    finally:
        stable = sources == {name: digest(ROOT / name) for name in sources}
        (output / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        (output / 'receipt.json').write_text(json.dumps(dict(passed=error is None and stable,
            terminal=True, source_stable=stable, error=error, cells=len(rows),
            matrix_complete=all(getattr(args, name) == 'both' for name in ('provider', 'linkage', 'firmware', 'transport')),
            timeout_seconds=90, host_repair_performed=False), indent=2) + '\n')
        for disk in output.rglob('*.raw'):
            archive_fixture(disk, remove=True)


if __name__ == '__main__':
    main()

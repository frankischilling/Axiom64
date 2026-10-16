#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify protected home claims across clean ext2 reboots on owned fixtures."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time

from account_home_test import SOURCES as HOME_SOURCES
from account_store_guest import fixture
from account_store_test import digest, environment
from build_musl import compiler_args
from ext2_test import create_volume
from fetch import ROOT
from fixture_archive import archive_fixture
from random_seed_crash_test import qemu_command

CLIENT = 'userspace/tests/security/account-home-reboot.c'
SOURCES = [*HOME_SOURCES, CLIENT, 'scripts/account_home_reboot_test.py']
NAMES = ('pending', 'published', 'nonempty', 'staged', 'unproven', 'replacement')
CLAIM = struct.Struct('<16sQIII40s4x')


def build(provider, linkage, directory):
    program = directory / 'account-home-reboot'
    command = [*compiler_args(provider), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               str(ROOT / 'userspace/accounts/home.c'), str(ROOT / 'userspace/accounts/protected.c'),
               str(ROOT / CLIENT), '-Wl,--wrap=mkdirat,--wrap=syscall,--wrap=fsetxattr',
               '-o', str(program), *(['-static'] if linkage == 'static' else [])]
    with (directory / 'compile.log').open('xb') as output:
        subprocess.run(command, cwd=ROOT, env=environment(), stdout=output,
                       stderr=subprocess.STDOUT, check=True)
    headers = subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True)
    assert ('INTERP' not in headers) == (linkage == 'static')
    return program, dict(command=command, binary_sha256=digest(program), headers=headers)


def execute(command, directory, phase, firmware):
    log = directory / (phase + '.log')
    started = time.monotonic_ns()
    with log.open('xb') as output:
        result = subprocess.run(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT, timeout=90)
    text = log.read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    marker = ('ACCOUNT_HOME_REBOOT_PREPARED cases=6' if phase == 'create'
              else 'ACCOUNT_HOME_REBOOT_PASS observations=8')
    observations = sum(line.startswith('ACCOUNT_HOME_REBOOT_OBSERVATION ') for line in lines)
    passed = (result.returncode == 1 and lines.count(marker) == 1
              and observations == (0 if phase == 'create' else 8)
              and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in lines
              and 'Firmware: ' + firmware.upper() in lines
              and not any(value in text for value in ('ACCOUNT_HOME_REBOOT_FAIL', 'PANIC:', 'FAULT pid=')))
    return dict(command=command, returncode=result.returncode, elapsed_ns=time.monotonic_ns() - started,
                log=str(log), log_sha256=digest(log), observations=observations, passed=passed)


def host_check(disk, directory, phase, original=None):
    records = []

    def read(command):
        result = subprocess.run(['debugfs', '-R', command, str(disk)], env=environment(),
                                check=True, capture_output=True)
        records.append(dict(command=command, stdout=result.stdout.decode(), stderr=result.stderr.decode()))
        return (result.stdout + result.stderr).decode()

    dumped = directory / (phase + '-claims.dump')
    read('dump /fixture/claims ' + str(dumped))
    payload = dumped.read_bytes()
    assert len(payload) == 528 and payload[:8] == b'A64HOME1'
    if original is not None:
        assert payload == original, 'persisted fixture key/identity manifest changed'
    boot = payload[8:48].rstrip(b'\0').decode()
    assert re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot)
    private = read('stat /fixture/claims')
    assert re.search(r'Mode:\s+0600\b', private) and re.search(r'User:\s+0\s+Group:\s+0\b', private)
    claims = []
    for index, name in enumerate(NAMES):
        key, inode, uid, gid, mode, staged = CLAIM.unpack_from(payload, 48 + CLAIM.size * index)
        assert any(key) and mode == 0o40700
        assert (uid, gid) == ((0, 0) if index == 4 else (1000, 1000))
        staged = staged.rstrip(b'\0').decode()
        assert bool(staged) == (index in (3, 4))
        if staged:
            assert re.fullmatch(r'\.home-[0-9a-f]{32}', staged)
        target = '/fixture/' + (staged or name)
        metadata = read('stat ' + target)
        removed = phase == 'verify' and index in (0, 3)
        if removed:
            assert 'File not found by ext2_lookup' in metadata
        else:
            assert int(re.search(r'Inode:\s+(\d+)', metadata)[1]) == inode
            assert int(re.search(r'Mode:\s+([0-7]+)', metadata)[1], 8) == (mode & 0o7777)
            actual = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+)', metadata)
            assert (int(actual[1]), int(actual[2])) == (uid, gid)
            attributes = read('ea_list ' + target)
            if index < 4:
                attribute = directory / (phase + '-' + name + '.attribute')
                read('ea_get -f ' + str(attribute) + ' ' + target + ' trusted.axiom64.home')
                assert attribute.read_bytes() == key
            else:
                assert 'trusted.axiom64.home' not in attributes
            if index in (1, 2):
                data = directory / (phase + '-' + name + '.data')
                read('dump /fixture/' + name + '/data ' + str(data))
                assert data.read_bytes() == b'preserved'
        claims.append(dict(name=name, inode=inode, uid=uid, gid=gid, mode=mode,
                           staged=staged, removed=removed, key_hex=key.hex()))
    (directory / (phase + '-host.json')).write_text(json.dumps(dict(
        boot=boot, claims=claims, commands=records, manifest_sha256=digest(dumped)), indent=2) + '\n')
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    args = parser.parse_args()
    args.directory = args.directory.resolve()
    assert args.directory.is_relative_to((ROOT / 'build').resolve())
    args.directory.mkdir(parents=True, exist_ok=False)
    names = [*SOURCES, *(path.relative_to(ROOT).as_posix() for path in (ROOT / 'kernel').rglob('*')
                        if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm'))]
    sources = {name: digest(ROOT / name) for name in names}
    (args.directory / 'source-inputs.json').write_text(json.dumps(sources, indent=2) + '\n')
    for name in sources:
        copied = args.directory / 'sources' / name
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, copied)
        assert digest(copied) == sources[name]
    rows, error = [], None
    try:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'],
                       cwd=ROOT, check=True)
        for provider in ('build', 'runtime'):
            for linkage in ('static', 'dynamic'):
                profile = args.directory / (provider + '-' + linkage)
                profile.mkdir()
                create = profile / 'create'
                create.mkdir()
                command = ('/bin/busybox mkdir -p /mnt/home-test\n'
                           '/bin/busybox mount -t ext2 /dev/vda /mnt/home-test\n'
                           '/bin/account-home-reboot create /mnt/home-test/fixture\n'
                           '/bin/busybox umount /mnt/home-test')
                create_image = fixture(create, provider, linkage, program_builder=build,
                                       filename='account-home-reboot', command=command)
                verified = profile / 'verify'
                verified.mkdir()
                provenance = json.loads((create / 'compiler-inputs.json').read_text())

                def same_program(_provider, _linkage, destination):
                    program = destination / 'account-home-reboot'
                    shutil.copyfile(create / 'account-home-reboot', program)
                    assert digest(program) == provenance['binary_sha256']
                    return program, provenance

                verify_image = fixture(verified, provider, linkage, program_builder=same_program,
                                       filename='account-home-reboot', command=command.replace(' create ', ' verify '))
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                        cell = profile / (firmware + '-' + transport)
                        cell.mkdir()
                        disk = cell / 'disk.raw'
                        create_volume(disk)
                        original = None
                        for phase, image in (('create', create_image), ('verify', verify_image)):
                            row = execute(qemu_command(cell, image, disk, firmware, transport), cell, phase, firmware)
                            row.update(provider=provider, linkage=linkage, firmware=firmware,
                                       transport=transport, phase=phase)
                            rows.append(row)
                            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                            if not row['passed']:
                                raise RuntimeError('home reboot failed: ' + str(cell) + '/' + phase)
                            log = cell / (phase + '-fsck.log')
                            with log.open('xb') as output:
                                checked = subprocess.run(['e2fsck', '-f', '-n', str(disk)], env=environment(),
                                                         stdout=output, stderr=subprocess.STDOUT)
                            if checked.returncode or re.search(
                                    r'count wrong|UNEXPECTED INCONSISTENCY|FILESYSTEM STILL HAS ERRORS',
                                    log.read_text(), re.I):
                                raise RuntimeError('home reboot filesystem is inconsistent')
                            row.update(fsck_returncode=checked.returncode, fsck_log_sha256=digest(log))
                            original = host_check(disk, cell, phase, original)
                            if phase == 'create':
                                checkpoint = cell / 'create-disk.raw'
                                shutil.copyfile(disk, checkpoint)
                                row['retained_disk'] = archive_fixture(checkpoint, remove=True)
                            else:
                                row['retained_disk'] = archive_fixture(disk, remove=True)
                            print('ACCOUNT_HOME_REBOOT_GUEST_PASS ' + profile.name + '/' + cell.name + '/' + phase, flush=True)
                            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    except BaseException as caught:
        error = repr(caught)
        raise
    finally:
        stable = sources == {name: digest(ROOT / name) for name in sources}
        (args.directory / 'receipt.json').write_text(json.dumps(dict(
            passed=error is None and stable, terminal=True, source_stable=stable, error=error,
            rows=len(rows), timeout_seconds=90), indent=2) + '\n')
    assert stable


if __name__ == '__main__':
    main()

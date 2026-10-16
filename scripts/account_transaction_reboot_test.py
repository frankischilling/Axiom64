#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Recover actual protected generation/home intents after a new kernel boot."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time
import zlib

from account_transaction_test import SOURCES as TRANSACTION_SOURCES, build
from account_store_guest import fixture
from account_store_test import digest, environment
from ext2_test import create_volume
from fetch import ROOT
from fixture_archive import archive_fixture
from random_seed_crash_test import qemu_command

SOURCES = [*TRANSACTION_SOURCES, 'scripts/account_transaction_reboot_test.py']
CASES = ('staged-intent', 'published-intent', 'staged-home', 'published-home',
         'claimed-generation', 'partial-generation', 'published-current', 'nonempty', 'replacement')


def execute(command, cell, phase, firmware):
    log = cell / (phase + '.log')
    started = time.monotonic_ns()
    with log.open('xb') as output:
        result = subprocess.run(command, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT, timeout=90)
    text = log.read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    marker = ('ACCOUNT_TRANSACTION_REBOOT_PREPARED cases=9' if phase == 'create'
              else 'ACCOUNT_TRANSACTION_REBOOT_PASS observations=10')
    count = sum(line.startswith('ACCOUNT_TRANSACTION_OBSERVATION ') for line in lines)
    passed = (result.returncode == 1 and lines.count(marker) == 1 and count == (0 if phase == 'create' else 10)
              and lines.count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in lines
              and 'Firmware: ' + firmware.upper() in lines
              and not any(value in text for value in ('ACCOUNT_TRANSACTION_FAIL', 'PANIC:', 'FAULT pid=')))
    return dict(command=command, returncode=result.returncode, elapsed_ns=time.monotonic_ns() - started,
                log=str(log), log_sha256=digest(log), observations=count, passed=passed)


def host_state(disk, cell, phase, expected=None):
    operations, states = [], {}

    def read(command):
        result = subprocess.run(['debugfs', '-R', command, str(disk)], env=environment(),
                                check=True, capture_output=True)
        operations.append(dict(command=command, stdout=result.stdout.decode(), stderr=result.stderr.decode()))
        return (result.stdout + result.stderr).decode()

    def dumped(path, name):
        output = cell / (phase + '-' + name)
        read('dump ' + path + ' ' + str(output))
        return output.read_bytes()

    def attribute(path, name, kind='trusted.axiom64.intent'):
        output = cell / (phase + '-' + name)
        read('ea_get -f ' + str(output) + ' ' + path + ' ' + kind)
        return output.read_bytes()

    for index, case in enumerate(CASES):
        base = '/fixture/' + case
        current = read('stat ' + base + '/store/current')
        revision = re.search(r'Fast link dest: "(g-[0-9a-f]{32})"', current)[1]
        state = dict(current=revision)
        intent = base + '/store/' + ('home-prepare' if index == 0 else 'home-intent')
        if phase == 'create' or index >= 7:
            metadata = read('stat ' + intent)
            assert re.search(r'Mode:\s+0600\b', metadata) and re.search(r'User:\s+0\s+Group:\s+0\b', metadata)
            payload = dumped(intent, case + '-intent.dump')
            assert payload[:8] == b'A64HOM01' and len(payload) >= 112
            before = payload[8:43].rstrip(b'\0').decode()
            after = payload[43:78].rstrip(b'\0').decode()
            key = payload[78:94]
            uid, gid, size = struct.unpack_from('<III', payload, 94)
            assert (uid, gid) == (1000, 1000) and size >= 2 and len(payload) == 110 + size
            assert struct.unpack_from('<I', payload, len(payload) - 4)[0] == zlib.crc32(payload[:-4])
            path = payload[106:-4].decode()
            assert path == '/mnt/transaction-test/fixture/' + case + '/homes/alice'
            assert re.fullmatch(r'g-[0-9a-f]{32}', before) and re.fullmatch(r'g-[0-9a-f]{32}', after)
            assert attribute(intent, case + '-intent.attribute') == key
            assert revision == (after if index == 6 else before)
            if phase == 'create' and index in (4, 5, 6):
                assert attribute(base + '/store/' + after, case + '-generation.attribute',
                                 'trusted.axiom64.generation') == key
            if phase == 'create' and index == 2:
                staged_home = base + '/homes/.home-' + key.hex()
                assert attribute(staged_home, case + '-home.attribute', 'trusted.axiom64.home') == key
            state.update(before=before, after=after, key_hex=key.hex(), intent_sha256=digest(cell / (phase + '-' + case + '-intent.dump')))
        else:
            assert 'File not found by ext2_lookup' in read('stat ' + intent)
            assert expected and revision == expected[case]['current']
        state['contents'] = {}
        for name in ('passwd', 'group', 'shadow'):
            state['contents'][name] = dumped(base + '/store/' + revision + '/' + name, case + '-' + name + '.dump').decode()
        if expected:
            assert state['contents'] == expected[case]['contents']
        home = base + '/homes/alice'
        if phase == 'verify' and index < 6:
            assert 'File not found by ext2_lookup' in read('stat ' + home)
        elif index >= 3:
            metadata = read('stat ' + home)
            inode = int(re.search(r'Inode:\s+(\d+)', metadata)[1])
            assert re.search(r'User:\s+1000\s+Group:\s+1000\b', metadata)
            state['home_inode'] = inode
            if expected:
                assert inode == expected[case]['home_inode']
            if index >= 6:
                assert dumped(home + '/data', case + '-data.dump') == b'preserved'
        states[case] = state
    (cell / (phase + '-host.json')).write_text(json.dumps(dict(states=states, operations=operations), indent=2) + '\n')
    return states


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
        target = args.directory / 'sources' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        assert digest(target) == sources[name]
    rows, error = [], None
    try:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox'], cwd=ROOT, check=True)
        for provider in ('build', 'runtime'):
            for linkage in ('static', 'dynamic'):
                profile = args.directory / (provider + '-' + linkage)
                profile.mkdir()
                create = profile / 'create'
                create.mkdir()
                command = ('/bin/busybox mkdir -p /mnt/transaction-test\n'
                           '/bin/busybox mount -t ext2 /dev/vda /mnt/transaction-test\n'
                           '/bin/account-transaction create /mnt/transaction-test/fixture\n'
                           '/bin/busybox umount /mnt/transaction-test')
                create_image = fixture(create, provider, linkage, program_builder=build,
                                       filename='account-transaction', command=command)
                verify = profile / 'verify'
                verify.mkdir()
                inputs = json.loads((create / 'compiler-inputs.json').read_text())

                def same(_provider, _linkage, target):
                    program = target / 'account-transaction'
                    shutil.copyfile(create / 'account-transaction', program)
                    assert digest(program) == inputs['binary_sha256']
                    return program, inputs

                verify_image = fixture(verify, provider, linkage, program_builder=same,
                                       filename='account-transaction', command=command.replace(' create ', ' verify '))
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                        cell = profile / (firmware + '-' + transport)
                        cell.mkdir()
                        disk = cell / 'disk.raw'
                        create_volume(disk)
                        expected = None
                        for phase, image in (('create', create_image), ('verify', verify_image)):
                            row = execute(qemu_command(cell, image, disk, firmware, transport), cell, phase, firmware)
                            row.update(provider=provider, linkage=linkage, firmware=firmware, transport=transport, phase=phase)
                            rows.append(row)
                            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                            if not row['passed']:
                                raise RuntimeError('transaction reboot failed: ' + str(cell) + '/' + phase)
                            log = cell / (phase + '-fsck.log')
                            with log.open('xb') as output:
                                checked = subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=output, stderr=subprocess.STDOUT)
                            if checked.returncode or re.search(r'count wrong|UNEXPECTED INCONSISTENCY|FILESYSTEM STILL HAS ERRORS', log.read_text(), re.I):
                                raise RuntimeError('transaction reboot filesystem is inconsistent')
                            row.update(fsck_returncode=checked.returncode, fsck_log_sha256=digest(log))
                            expected = host_state(disk, cell, phase, expected)
                            if phase == 'create':
                                copy = cell / 'create-disk.raw'
                                shutil.copyfile(disk, copy)
                                row['retained_disk'] = archive_fixture(copy, remove=True)
                            else:
                                row['retained_disk'] = archive_fixture(disk, remove=True)
                            print('ACCOUNT_TRANSACTION_REBOOT_GUEST_PASS ' + profile.name + '/' + cell.name + '/' + phase, flush=True)
                            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    except BaseException as caught:
        error = repr(caught)
        raise
    finally:
        stable = sources == {name: digest(ROOT / name) for name in sources}
        (args.directory / 'receipt.json').write_text(json.dumps(dict(passed=error is None and stable,
            terminal=True, source_stable=stable, error=error, rows=len(rows), timeout_seconds=90), indent=2) + '\n')
    assert stable


if __name__ == '__main__':
    main()

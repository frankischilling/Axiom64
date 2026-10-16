#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Rotate the production-size journal on persistent ext2 and reopen after reboot."""
import argparse
import binascii
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

from account_logbook_rotation_guest import (ARCHIVE_FILES, INPUTS, MODES, build, execute,
                                           frames, projections, qemu, state, verify_default)
from account_logbook_rotation_ext2 import fsck
from account_management_ext2 import working_disk
from account_store_guest import fixture
from account_store_test import digest
from ext2_test import SEED, create_volume, debugfs
from fetch import ROOT
from fixture_archive import archive_fixture

ARCHIVE = 'archive-0000000000000001'
CAPACITY = 33554432 // 448


def native_files(disk, directory, base):
    check = fsck(disk, directory, 'strict')
    assert check['passed'] and 'skipping journal recovery' not in (directory / 'strict-fsck.log').read_text()
    expected_names = set(MODES) | {ARCHIVE + '/' + name for name in ARCHIVE_FILES}
    for suffix, wanted in [('', set(MODES) | {ARCHIVE}), ('/' + ARCHIVE, set(ARCHIVE_FILES))]:
        listing = debugfs(disk, 'ls -p /records' + suffix)
        (directory / ('listing' + suffix.replace('/', '-') + '.log')).write_text(listing)
        actual = {line.split('/')[5] for line in listing.splitlines() if line.startswith('/')}
        assert actual - {'.', '..'} == wanted
    exported = directory / 'exports'
    exported.mkdir()
    files, metadata = {}, {}
    for name in ['.', ARCHIVE, *sorted(expected_names)]:
        path = '/records' + ('/' + name if name != '.' else '')
        text = debugfs(disk, 'stat ' + path)
        (directory / ('stat-' + name.replace('/', '-') + '.log')).write_text(text)
        kind = re.search(r'Type:\s+(\S+)\s+Mode:\s+([0-7]+)', text)
        owner = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', text)
        links = re.search(r'Links:\s+(\d+)', text)
        assert kind and owner and links
        is_directory = name in ('.', ARCHIVE)
        mode = 0o755 if is_directory else MODES[name.rsplit('/', 1)[-1]]
        assert (kind[1], int(kind[2], 8), int(owner[1]), int(owner[2]), int(links[1])) == (
            'directory' if is_directory else 'regular', mode, 0, 0,
            3 if name == '.' else 2 if is_directory else 1), name
        metadata[name] = dict(kind=kind[1], mode=mode, uid=0, gid=0, links=int(links[1]), bytes=int(owner[3]))
        if not is_directory:
            target = exported / name
            target.parent.mkdir(parents=True, exist_ok=True)
            debugfs(disk, 'dump ' + path + ' ' + str(target))
            files[name] = target.read_bytes()
            assert len(files[name]) == int(owner[3])
    saved = state(files['state'])
    archived = state(files[ARCHIVE + '/state'])
    assert saved == dict(generation=2, carried=0, previous_events=CAPACITY)
    assert archived == dict(generation=1, carried=0, previous_events=0)
    current = frames(files['journal'])
    assert len(current) == 1
    assert (current[0]['kind'], current[0]['uid'], current[0]['gid'], current[0]['user'],
            current[0]['target'], current[0]['status']) == (5, 70000, 0, 'alice', 'root', 65535)
    archive = files[ARCHIVE + '/journal']
    assert len(archive) == CAPACITY * 448
    first = frames(base)[0]
    assert first['kind'] == 5 and first['uid'] == 70000 and not first['status']
    for sequence in range(1, CAPACITY + 1):
        expected = bytearray(base)
        struct.pack_into('<Q', expected, 16, sequence)
        expected[12:16] = bytes(4)
        struct.pack_into('<I', expected, 12, binascii.crc32(expected))
        assert archive[(sequence - 1) * 448:sequence * 448] == expected
    for prefix, policy, records in [('', saved, current), (ARCHIVE + '/', archived, [first] * CAPACITY)]:
        for name, data in projections(policy, records).items():
            assert files[prefix + name] == data, prefix + name
    assert not files['utmp'] and not files['lock']
    seed = directory / 'seed.txt'
    debugfs(disk, 'dump /seed.txt ' + str(seed))
    assert seed.read_bytes() == SEED
    proof = dict(passed=True, strict_fsck=check, metadata=metadata,
                 sha256={name: digest(exported / name) for name in files},
                 archive_crc32=f'{binascii.crc32(archive):08x}',
                 frames=CAPACITY, production_limit=33554432, live_limit=1024)
    (directory / 'native-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    return proof


def cell(directory, provider, linkage, firmware, transport):
    directory.mkdir()
    disk = directory / 'disk.raw'
    create_volume(disk, capacity=256 * 1024**2)
    created = subprocess.run(['tune2fs', '-j', str(disk)], capture_output=True, text=True)
    (directory / 'journal-create.log').write_text(created.stdout + created.stderr)
    assert created.returncode == 0
    with disk.open('rb') as stream:
        stream.seek(1116)
        assert struct.unpack('<I', stream.read(4))[0] & 4
    program, inputs = build(provider, linkage, directory, default=True)
    assert inputs['journal_limit'] == 33554432 and inputs['live_limit'] == 1024 and not inputs['wrapped']
    row = dict(passed=False, provider=provider, linkage=linkage, firmware=firmware,
               transport=transport, timeout_seconds=600, fixture_bytes=disk.stat().st_size,
               inputs=inputs, phases=[], reduced_limits=False, power_loss=False)
    base = None
    original = None
    try:
        for phase in ('default', 'default-recover'):
            folder = directory / phase
            folder.mkdir()
            command = ('/bin/busybox mkdir -p /mnt/production-records\n'
                       '/bin/busybox mount -t ext2 /dev/vda /mnt/production-records\n'
                       '/bin/account-rotation-production-' + phase + ' ' + phase +
                       ' /mnt/production-records/records\n'
                       '/bin/busybox umount /mnt/production-records')
            image = fixture(folder, provider, linkage, program_builder=lambda *unused: (program, inputs),
                            filename='account-rotation-production-' + phase, command=command)
            input_hash = digest(disk)
            with working_disk(disk) as device:
                run = execute(qemu(image, folder, firmware, transport, disk=device, memory=512),
                              folder / 'guest.log', timeout=600)
            run.update(phase=phase, image_sha256=digest(image), input_disk_sha256=input_hash,
                       final_disk_sha256=digest(disk))
            row['phases'].append(run)
            text = (folder / 'guest.log').read_text().replace('\r\n', '\n')
            marker = 'ACCOUNT_ROTATION_GUEST_PASS phase=' + phase + ' policy=33554432 generation=2 archives=1'
            assert not run['timed_out'] and run['returncode'] == 1
            assert text.splitlines().count(marker) == 1
            assert text.splitlines().count('AXIOM64_TESTS_PASS') == text.splitlines().count('AXIOM64_EXIT status=0') == 1
            assert 'Firmware: ' + firmware.upper() in text
            assert 'virtio-blk: disk=0 transport=' + transport + ' sectors=524288 readonly=0 flush=1' in text
            assert not any(word in text for word in ('ACCOUNT_ROTATION_GUEST_FAIL', 'PANIC:', 'FAULT pid='))
            if phase == 'default':
                run['default_proof'] = verify_default(folder / 'guest.log')
                captures = re.findall(r'^ACCOUNT_ROTATION_GUEST_DEFAULT_BASE ([0-9a-f]{896})$', text, re.M)
                assert len(captures) == 1
                base = bytes.fromhex(captures[0])
            native = native_files(disk, folder, base)
            run['native'] = native
            if original is None:
                original = native['sha256']
                retained = directory / 'before-reboot.raw'
                shutil.copyfile(disk, retained)
                run['retained_disk'] = archive_fixture(retained, remove=True)
            else:
                assert original == native['sha256'], 'reopening changed authoritative history or projections'
                found = re.findall(r'^ACCOUNT_ROTATION_GUEST_DEFAULT_RECOVERY frames=(\d+) bytes=(\d+) crc32=([0-9a-f]{8})$', text, re.M)
                assert found == [(str(CAPACITY), str(CAPACITY * 448), native['archive_crc32'])]
                assert input_hash == row['phases'][0]['final_disk_sha256']
            run['passed'] = True
            print('ACCOUNT_ROTATION_DEFAULT_EXT2_PHASE_PASS ' + directory.name + '/' + phase, flush=True)
        row.update(passed=True, clean_reboot=True)
    finally:
        row['retained_final'] = archive_fixture(disk, remove=True)
        (directory / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    for name, choices in [('provider', ('build', 'runtime')), ('linkage', ('static', 'dynamic')),
                          ('firmware', ('bios', 'uefi')), ('transport', ('modern', 'legacy'))]:
        parser.add_argument('--' + name, choices=(*choices, 'both'), default='both')
    args = parser.parse_args()
    args.directory = args.directory.resolve()
    if os.geteuid() or not args.directory.is_relative_to((ROOT / 'build').resolve()):
        parser.error('run as root with a new owned build directory')
    args.directory.mkdir(parents=True, exist_ok=False)
    helpers = [Path(module.__file__).relative_to(ROOT).as_posix() for module in list(sys.modules.values())
               if getattr(module, '__file__', None) and Path(module.__file__).is_file()
               and Path(module.__file__).is_relative_to(ROOT / 'scripts')]
    names = set([*INPUTS, 'scripts/account_logbook_default_ext2.py', *helpers,
                 *(p.relative_to(ROOT).as_posix() for p in (ROOT / 'kernel').rglob('*')
                                      if p.is_file() and p.suffix in ('.cpp', '.hpp', '.asm'))])
    sources = {name: digest(ROOT / name) for name in sorted(names)}
    products = {name: digest(ROOT / name) for name in ('build/axiom64.elf', 'build/init')}
    (args.directory / 'source-inputs.json').write_text(json.dumps(sources, indent=2) + '\n')
    for name in sources:
        target = args.directory / 'source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    receipt = dict(passed=False, terminal=False, rows=[], source_stable=False,
                   production_limit=33554432, live_limit=1024, timeout_seconds=600,
                   frozen_products=products, selection={name: getattr(args, name) for name in
                                                       ('provider', 'linkage', 'firmware', 'transport')})
    save = lambda: (args.directory / 'acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n')
    try:
        save()
        choices = [values if getattr(args, name) == 'both' else (getattr(args, name),) for name, values in
                   [('provider', ('build', 'runtime')), ('linkage', ('static', 'dynamic')),
                    ('firmware', ('bios', 'uefi')), ('transport', ('modern', 'legacy'))]]
        for scope in itertools.product(*choices):
            receipt['rows'].append(cell(args.directory / '-'.join(scope), *scope))
            save()
        receipt['passed'] = True
    except BaseException as error:
        receipt['error'] = repr(error)
        raise
    finally:
        receipt.update(terminal=True, source_stable=all(digest(ROOT / name) == value for name, value in sources.items()),
                       products_stable=all(digest(ROOT / name) == value for name, value in products.items()))
        receipt['passed'] = receipt['passed'] and receipt['source_stable'] and receipt['products_stable']
        save()
    assert receipt['passed']
    print('ACCOUNT_ROTATION_DEFAULT_EXT2_PASS cells=' + str(len(receipt['rows'])), flush=True)


if __name__ == '__main__':
    main()

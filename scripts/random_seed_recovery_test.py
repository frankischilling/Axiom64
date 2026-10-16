#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate dirty ext2 recovery policy and reject the complete malformed corpus."""
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

from ext2_test import create_volume, debugfs, invalid_volumes, recovery_volumes, SEED
from fetch import ROOT
from random_administration_test import checked_run, fingerprint, snapshot
from random_seed_crash_test import qemu_command
from random_seed_test import image


def invalid(directory):
    prefix = directory / ('invalid-' + directory.name)
    result = []
    for source in invalid_volumes(prefix):
        data = bytearray(source.read_bytes())
        struct.pack_into('<H', data, 1024 + 58, 0)
        if source.stem.endswith('-free-count'):
            # In-range summaries are recoverable. Keep this negative case for
            # an out-of-range total, which must reject before any mount writes.
            blocks = struct.unpack_from('<I', data, 1024 + 4)[0]
            struct.pack_into('<I', data, 1024 + 12, blocks + 1)
        source.write_bytes(data)
        expected = int(re.match(rb'AXIOM64_EXT2_EXPECT=(\d+)\n', data)[1])
        result.append((source, expected))
    original = Path(str(prefix) + '-base.raw').read_bytes()
    for name, state, orphan in (('error-state', 2, 0), ('clean-error-state', 3, 0),
                                ('orphan-chain', 0, 16)):
        data = bytearray(original)
        struct.pack_into('<H', data, 1024 + 58, state)
        struct.pack_into('<I', data, 1024 + 232, orphan)
        marker = b'AXIOM64_EXT2_EXPECT=117\n'
        data[:len(marker)] = marker
        source = directory / (name + '.raw')
        source.write_bytes(data)
        result.append((source, 117))
    if len(result) != 26:
        raise RuntimeError('the dirty-volume rejection corpus is incomplete')
    return result


def boot(case, iso, volumes, linkage, firmware, transport, mode):
    case.mkdir()
    copies, before = [], {}
    for index, (source, expected) in enumerate(volumes):
        disk = case / (str(index) + '-' + source.name)
        shutil.copyfile(source, disk)
        before[disk.name] = dict(input=fingerprint(disk), expected_error=expected)
        copies.append(disk)
    command = qemu_command(case, iso, copies[0], firmware, transport)
    for index, disk in enumerate(copies[1:], 1):
        command += ['-drive', f'if=none,format=raw,cache=writeback,file={disk},id=extra{index}',
                    '-device', f'virtio-blk-pci,drive=extra{index},' +
                    ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    row, text = checked_run(command, case / 'guest.log', 90)
    row.update(linkage=linkage, firmware=firmware, transport=transport, mode=mode,
               image=fingerprint(iso), before=before)
    checks = 9 if mode == 'policy' else len(volumes)
    required = [f'RANDOM_SEED_RECOVERY_PASS linkage={linkage} mode={mode} checks={checks}\n',
                'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}']
    try:
        if row['returncode'] != 1 or row['timed_out'] or any(marker not in text for marker in required):
            raise RuntimeError('dirty-volume recovery policy did not pass')
        if any(marker in text for marker in ('RANDOM_SEED_RECOVERY_FAIL ', 'PANIC:', 'FAULT pid=')):
            raise RuntimeError('the recovery policy guest reported a failure')
        row['after'] = {disk.name: fingerprint(disk) for disk in copies}
        if mode == 'invalid':
            if any(before[disk.name]['input'] != row['after'][disk.name] for disk in copies):
                raise RuntimeError('checked recovery wrote to a rejected disk')
            observations = re.findall(r'RANDOM_SEED_RECOVERY_REJECT device=/dev/vd([a-h]) '
                                      r'type=ext2 flags=0 error=(\d+)\n', text)
            if observations != [(chr(ord('a') + index), str(expected))
                                for index, (_, expected) in enumerate(volumes)]:
                raise RuntimeError('the actual malformed-volume error observations differ')
            row['rejections'] = observations
        else:
            filesystems = {}
            for index, disk in enumerate(copies):
                logfile = case / ('fsck.log' if mode == 'policy' else f'fsck-{index}.log')
                with logfile.open('wb') as output:
                    result = subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=output,
                                            stderr=subprocess.STDOUT)
                if result.returncode or re.search(
                        r'count wrong|UNEXPECTED INCONSISTENCY|FILESYSTEM STILL HAS ERRORS',
                        logfile.read_text(), re.I):
                    raise RuntimeError('checked recovery did not leave a clean filesystem')
                filesystems[disk.name] = dict(returncode=result.returncode, log=fingerprint(logfile))
                if debugfs(disk, 'cat /seed.txt').encode() != SEED:
                    raise RuntimeError('checked recovery changed the original seed file')
            row['filesystem'] = filesystems[copies[0].name]
            row['filesystems'] = filesystems
            if mode == 'counters':
                expected = []
                for index, (source, _) in enumerate(volumes):
                    marker = re.match(rb'AXIOM64_EXT2_RECOVER=1,117,(\d+),(\d+),117\n',
                                      source.read_bytes()[:128])
                    if not marker:
                        raise RuntimeError('counter fixture lacks independently prepared totals')
                    expected.append((chr(ord('a') + index), marker[1].decode(), marker[2].decode()))
                observed = re.findall(r'RANDOM_SEED_RECOVERY_COUNTER device=/dev/vd([a-h]) '
                                      r'free_blocks=(\d+) free_inodes=(\d+)\n', text)
                if observed != expected:
                    raise RuntimeError('the actual reconciled counter observations differ')
                row['counter_observations'] = observed
        row['passed'] = True
    except BaseException as error:
        row.update(passed=False, error=repr(error))
        raise
    finally:
        (case / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--checks', choices=('policy', 'invalid', 'both'), default='both')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-seed-recovery-results')
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    linkages = ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    *(f'build/{program}-{linkage}' for linkage in linkages for program in
                      ('random-seed', 'random', 'random-seed-recovery'))], cwd=ROOT, check=True)
    inputs = snapshot(directory)
    for name in ('userspace/tests/random/seed_recovery.c', 'scripts/random_seed_recovery_test.py',
                 'scripts/ext2_test.py', 'scripts/random_seed_crash_test.py', 'scripts/random_seed_test.py',
                 'scripts/image.py', 'userspace/services/random_seed.c'):
        inputs[name] = fingerprint(ROOT / name)
    (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    policies = []
    counters = []
    if args.checks in ('policy', 'both'):
        for block_size, inode_size, features in ((1024, 128, 'default'), (2048, 256, 'default'),
                                                (4096, 256, 'default'), (1024, 128, 'original')):
            disk = directory / f'policy-{block_size}-{inode_size}-{features}.raw'
            create_volume(disk, block_size, inode_size, features)
            data = bytearray(disk.read_bytes())
            struct.pack_into('<H', data, 1024 + 58, 0)
            disk.write_bytes(data)
            policies.append([(disk, 0)])
            prefix = directory / f'counters-{block_size}-{inode_size}-{features}'
            counters.append([(disk, 0) for disk, repaired in
                             recovery_volumes(prefix, block_size, inode_size, features) if repaired])
    damaged = invalid(directory) if args.checks in ('invalid', 'both') else []
    results = []
    for linkage in linkages:
        images = {}
        image_cases = [('policy', 0)] * bool(policies) + [('counters', 6)] * bool(counters)
        image_cases += [('invalid', count) for count in (8, 2)] * bool(damaged)
        for mode, count in image_cases:
            folder = directory / (linkage + '-' + mode + str(count) + '-image')
            folder.mkdir()
            images[mode, count] = image(folder, linkage, 'recovery-' + mode + str(count),
                probe='random-seed-recovery', command='/bin/seed-probe ' + mode +
                (' ' + str(count) if mode != 'policy' else ''))
        for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
            for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                selected = [('policy', index, volumes) for index, volumes in enumerate(policies)]
                selected += [('counters', index, volumes) for index, volumes in enumerate(counters)]
                selected += [('invalid', index // 8, damaged[index:index+8])
                             for index in range(0, len(damaged), 8)]
                for mode, index, volumes in selected:
                    case = directory / f'{linkage}-{firmware}-{transport}-{mode}-{index}'
                    results.append(boot(case, images[mode, len(volumes) if mode != 'policy' else 0],
                                        volumes, linkage, firmware, transport, mode))
                    (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                    print(json.dumps(dict(case=case.name, passed=True, volumes=len(volumes))), flush=True)
    if not results or inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('checked recovery source changed or no selected case ran')


if __name__ == '__main__':
    main()

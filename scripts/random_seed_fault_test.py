#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail actual virtio seed-storage requests and independently verify recovery."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from fetch import ROOT
from random_administration_test import checked_run, fingerprint, snapshot
from random_seed_test import blank_disk, disk_state, image

OLD = bytes(range(32))


def debugfs(path, command, directory, label, write=False):
    result = subprocess.run(['debugfs', *(['-w'] if write else []), '-R', command, str(path)],
                            capture_output=True, text=True,
                            env=dict(os.environ, E2FSPROGS_FAKE_TIME='1700000000'), check=True)
    (directory / (label + '.log')).write_text(result.stdout + result.stderr)
    return result


def base(directory, full):
    label = 'full' if full else 'io'
    disk = directory / ('base-' + label + '.raw')
    blank_disk(disk)
    old = directory / 'old-seed.bin'
    old.write_bytes(OLD)
    empty = directory / 'empty.bin'
    empty.write_bytes(b'')
    commands = ['mkdir /random', 'sif /random mode 040700',
                'write ' + json.dumps(str(old)) + ' /random/seed', 'sif /random/seed mode 0100600',
                'write ' + json.dumps(str(empty)) + ' /random/lock', 'sif /random/lock mode 0100600']
    for index, command in enumerate(commands):
        result = debugfs(disk, command, directory, f'{label}-create-{index}', write=True)
        if any(marker in result.stderr for marker in ('not found', 'Could not allocate', 'File exists')):
            raise RuntimeError('seed fixture creation failed')
    if full:
        blob = directory / 'full-input.bin'
        blob.write_bytes(b'\x63' * (32 * 1024 * 1024))
        debugfs(disk, 'write ' + json.dumps(str(blob)) + ' /fill', directory, 'full-fill', write=True)
    result = subprocess.run(['dumpe2fs', '-h', str(disk)], capture_output=True, text=True, check=True)
    (directory / (label + '-superblock.log')).write_text(result.stdout + result.stderr)
    free = int(re.search(r'^Free blocks:\s+(\d+)$', result.stdout, re.MULTILINE)[1])
    if (free == 0) != full:
        raise RuntimeError('the seed fixture does not have the intended actual free-block count')
    state = disk_state(disk, directory, 'base-' + label)
    if (directory / ('base-' + label + '-seed.bin')).read_bytes() != OLD:
        raise RuntimeError('the initial seed disk does not contain the specified payload')
    return disk, dict(state=state, free_blocks=free)


def rule(path, event, number):
    text = ''
    for state in range(1, number):
        text += ('[set-state]\nevent = "' + event + '"\nstate = "' + str(state) +
                 '"\nnew_state = "' + str(state + 1) + '"\n\n')
    text += ('[inject-error]\nevent = "' + event + '"\nstate = "' + str(number) +
             '"\niotype = "' + ('flush' if event == 'flush_to_disk' else 'write') +
             '"\nerrno = "5"\nonce = "on"\n')
    path.write_text(text)


def boot(directory, label, iso, base_disk, base_state, linkage, firmware, transport, mode, event, number):
    case = directory / label
    case.mkdir()
    disk = case / 'disk.raw'
    shutil.copyfile(base_disk, disk)
    if fingerprint(disk) != base_state['state']['disk']:
        raise RuntimeError('seed fault disk differs from its verified base')
    backend = str(disk)
    rules = None
    if mode == 'io':
        rules = case / 'fault.conf'
        rule(rules, event, number)
        backend = f'blkdebug:{rules}:{disk}'
    trace = case / 'block.trace'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
               '-nic', 'none', '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,format=raw,cache=writeback,file={backend},id=seed',
               '-device', 'virtio-blk-pci,drive=seed,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on'),
               '-trace', f'enable=virtio_blk_req_complete,file={trace}']
    firmware_inputs = {}
    if firmware == 'uefi':
        variables = case / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        firmware_inputs = {name: fingerprint(Path('/usr/share/OVMF') / name) for name in
                           ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd')}
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    row, text = checked_run(command, case / 'guest.log', 90)
    row.update(label=label, linkage=linkage, firmware=firmware, transport=transport, mode=mode,
               event=event, request=number, before=base_state, image=fingerprint(iso),
               firmware_inputs=firmware_inputs)
    try:
        required = [f'RANDOM_SEED_FAULT_PASS linkage={linkage} mode={mode} ',
                    f'Firmware: {firmware.upper()}', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                    'RANDOM_READY source=rdseed bits=256']
        if row['timed_out'] or row['returncode'] != 1 or any(marker not in text for marker in required):
            raise RuntimeError('the actual seed fault guest did not complete: ' + label)
        if any(marker in text for marker in ('RANDOM_SEED_FAULT_FAIL ', 'PANIC:', 'FAULT pid=')):
            raise RuntimeError('the seed fault guest reported a failure')
        errors = re.findall(r'RANDOM_SEED_FAILED stage=(\S+) error=(\d+)', text)
        io_errors = len(re.findall(r'virtio_blk_req_complete .*?status 1\b', trace.read_text()))
        row.update(service_errors=errors, io_errors=io_errors, trace=fingerprint(trace),
                   rules=fingerprint(rules) if rules else None)
        if mode == 'io':
            if io_errors != 1:
                raise RuntimeError('the device did not complete exactly one actual failed block request')
            status = int(re.search(r'RANDOM_SEED_FAULT_PASS .*?first_status=(\d+)', text)[1])
            if status == 1:
                if len(errors) != 1 or errors[0][1] != '5':
                    raise RuntimeError('the seed service did not expose the injected EIO')
            elif errors or 'RANDOM_SEED_ROTATED bytes=32 previous=1 cleanup_pending=1' not in text:
                raise RuntimeError('a committed cleanup fault was not reported')
        elif len(errors) != 1 or errors[0][1] != '28' or io_errors:
            raise RuntimeError('the full actual filesystem did not produce ENOSPC')
        payloads = re.findall(r'RANDOM_SEED_FAULT_PAYLOAD state=(\S+) inode=(\d+) links=(\d+) '
                              r'value=([0-9a-f]{64})', text)
        if len(payloads) != 3 or payloads[0][0] != 'original' or payloads[-1][0] != 'retry':
            raise RuntimeError('the guest did not retain all actual payload observations')
        if bytes.fromhex(payloads[0][3]) != OLD or int(payloads[0][1]) != base_state['state']['random/seed']['inode']:
            raise RuntimeError('the guest initial seed differs from independent host metadata and bytes')
        if payloads[1][0] == 'preserved':
            if payloads[0][1] != payloads[1][1] or payloads[0][3] != payloads[1][3]:
                raise RuntimeError('an uncommitted failure lost the original seed')
        elif payloads[1][0] != 'committed' or payloads[1][3] == payloads[0][3]:
            raise RuntimeError('a committed replacement was not complete and different')
        row['after'] = disk_state(disk, case, 'after')
        if (case / 'after-seed.bin').read_bytes() != bytes.fromhex(payloads[-1][3]):
            raise RuntimeError('independent disk export differs from the guest retry')
        if payloads[-1][3] == payloads[1][3]:
            raise RuntimeError('the checked retry did not rotate the seed')
        listing = debugfs(disk, 'ls -p /random', case, 'after-directory').stdout
        names = {line.split('/')[5] for line in listing.splitlines() if line.startswith('/')}
        if names != {'.', '..', 'seed', 'lock'}:
            raise RuntimeError('recovery left unexpected seed directory entries: ' + repr(names))
        row.update(passed=True, payloads=payloads)
    except BaseException as error:
        row.update(passed=False, error=repr(error))
        raise
    finally:
        (case / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
    print(json.dumps(dict(case=label, passed=True, errors=errors, io_errors=io_errors)), flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--mode', choices=('io', 'full'), nargs='+', default=['io', 'full'])
    parser.add_argument('--event', choices=('flush_to_disk', 'write_aio', 'both'), default='both')
    parser.add_argument('--request', type=int, nargs='+')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-seed-fault-results')
    args = parser.parse_args()
    if args.request and not all(2 <= number <= 64 for number in args.request):
        parser.error('fault request numbers must be bounded and follow the mount operation')
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    linkages = ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    *(f'build/{program}-{linkage}' for linkage in linkages
                      for program in ('random-seed', 'random-seed-fault', 'random'))], cwd=ROOT, check=True)
    inputs = snapshot(directory)
    for name in ('userspace/tests/random/seed_fault.c', 'userspace/services/random_seed.c',
                 'scripts/random_seed_test.py', 'scripts/random_seed_fault_test.py',
                 'scripts/image.py', 'scripts/disk_root.py', 'userspace/init/main.c'):
        inputs[name] = fingerprint(ROOT / name)
    (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    tools = {}
    for name in ('qemu-system-x86_64', 'debugfs', 'e2fsck', 'mke2fs', 'dumpe2fs'):
        binary = Path(shutil.which(name)).resolve()
        tools[name] = dict(path=str(binary), input=fingerprint(binary))
    tools['qemu-system-x86_64']['version'] = subprocess.check_output(
        ['qemu-system-x86_64', '--version'], text=True)
    (directory / 'tools.json').write_text(json.dumps(tools, indent=2) + '\n')
    bases = {mode: base(directory, mode == 'full') for mode in args.mode}
    results = []
    for linkage in linkages:
        images = {}
        for mode in args.mode:
            case = directory / (linkage + '-' + mode + '-image')
            case.mkdir()
            images[mode] = image(case, linkage, mode, probe='random-seed-fault',
                                 command='/bin/seed-probe ' + mode)
        for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
            for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                for mode in args.mode:
                    events = ('flush_to_disk', 'write_aio') if args.event == 'both' else (args.event,)
                    for event in events if mode == 'io' else ('none',):
                        # The first flush commits mount state. Flushes2..7 belong
                        # to rotation;8 belongs to the independent retry. These
                        # bounds follow the retained actual request probes.
                        requests = args.request or list(range(2, 8 if event == 'flush_to_disk' else 11))
                        for number in requests if mode == 'io' else (0,):
                            label = f'{linkage}-{firmware}-{transport}-{mode}-{event}-{number}'
                            results.append(boot(directory, label, images[mode], *bases[mode], linkage,
                                                firmware, transport, mode, event, number))
                            (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    if inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('source changed during actual seed disk-failure comparisons')


if __name__ == '__main__':
    main()

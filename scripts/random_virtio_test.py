#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual virtio RNG transports with explicit trust and failed sources."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

from fetch import ROOT
from random_administration_test import checked_run, fingerprint, fixture, snapshot
from random_entropy_peer import EntropyPeer

CASES = ('trusted', 'short', 'untrusted', 'zero', 'ones', 'repeated-word', 'timeout', 'absent')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    p.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    p.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    p.add_argument('--case', choices=CASES, nargs='+', default=list(CASES))
    p.add_argument('--reseed', action='store_true')
    p.add_argument('--output', type=Path)
    p.add_argument('--timeout', type=float, default=90)
    args = p.parse_args()
    if args.timeout <= 0 or (args.reseed and args.timeout < 70):
        p.error('use a positive timeout, at least 70 seconds for real reseeding')
    directory = args.output or ROOT / 'build/random-virtio-results'
    if directory.exists():
        raise RuntimeError('use a new output directory to preserve earlier evidence')
    directory.mkdir(parents=True)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init',
                    'build/random-static', 'build/random-dynamic', 'busybox'], cwd=ROOT, check=True)
    inputs = snapshot(directory)
    inputs['userspace/tests/random/random.c'] = fingerprint(ROOT / 'userspace/tests/random/random.c')
    inputs['scripts/random_virtio_test.py'] = fingerprint(Path(__file__).resolve())
    inputs['scripts/random_entropy_peer.py'] = fingerprint(ROOT / 'scripts/random_entropy_peer.py')
    (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    results, samples = [], set()
    for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
        for case in args.case:
            ready = case in ('trusted', 'short')
            mode = 'ready-reseed' if args.reseed and case == 'trusted' else (
                'ready' if ready else 'unready-delayed' if case == 'timeout' else 'unready')
            trusted = case != 'untrusted'
            case_directory = directory / f'{linkage}-{case}'
            case_directory.mkdir()
            options = ['random.trust_cpu=off']
            if trusted:
                options += ['random.trust_virtio=on']
            wait = '/bin/busybox dd if=/dev/random of=/dev/null bs=1 count=1' if ready else ''
            image = fixture(case_directory, linkage, mode, program='random', options=options, before=wait)
            backend = '/dev/urandom'
            if case in ('zero', 'ones', 'repeated-word'):
                data = {'zero': b'\x00', 'ones': b'\xff', 'repeated-word': b'ABCDEFGH'}[case]
                source = case_directory / 'failed-entropy-source.bin'
                source.write_bytes(data * (131072 // len(data)))
                backend = str(source.resolve())
            transports = (None,) if case == 'absent' else (
                ('modern', 'legacy') if args.transport == 'both' else (args.transport,))
            for transport in transports:
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    tag = f'{transport}-{firmware}'
                    serial = case_directory / f'{tag}.log'
                    peer = None
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu',
                               'max,rdseed=off,rdrand=off', '-m', '256M', '-nic', 'none',
                               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                               '-monitor', 'none', '-no-reboot', '-device',
                               'isa-debug-exit,iobase=0xf4,iosize=0x04']
                    if case != 'absent':
                        quota = ',max-bytes=7,period=10' if case == 'short' else (
                            ',max-bytes=1,period=5000' if case == 'timeout' and firmware == 'bios' else '')
                        transport_option = 'disable-legacy=on' if transport == 'modern' else 'disable-modern=on'
                        if case == 'timeout' and firmware == 'uefi':
                            # Firmware also consumes this device. Withhold only after
                            # the real kernel source marker, keeping its deadline intact.
                            peer = EntropyPeer(serial, case_directory / f'{tag}-peer.json')
                            command += peer.qemu_arguments()
                        else:
                            command += ['-object', f'rng-random,id=entropy,filename={backend}']
                        command += ['-device', f'virtio-rng-pci,rng=entropy,{transport_option}{quota}']
                    if firmware == 'uefi':
                        variables = case_directory / f'{tag}-OVMF_VARS.fd'
                        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', f'if=pflash,format=raw,file={variables}']
                    try:
                        row, text = checked_run(command, serial, args.timeout)
                    finally:
                        if peer:
                            peer.close()
                    if peer:
                        row['entropy_peer'] = peer.validate(serial)
                        row['entropy_peer_input'] = fingerprint(peer.evidence)
                    markers = [f'RANDOM_TEST_PASS linkage={linkage} mode={mode}',
                               'RANDOM_FLAGS_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                               f'Firmware: {firmware.upper()}', 'RANDOM_SOURCE rdseed=0 trust_cpu=0']
                    if case != 'absent':
                        markers += [f'RANDOM_VIRTIO_SOURCE transport={transport} trusted={int(trusted)}']
                    if ready:
                        markers += ['RANDOM_READY source=virtio bits=256', 'RANDOM_READY_PASS',
                                    'RANDOM_CONCURRENT_PASS processes=8 samples=distinct']
                    else:
                        markers += ['RANDOM_UNREADY_PASS'] + [
                            f'RANDOM_WAIT_PASS operation={operation} restart={restart} '
                            f'result={"retry" if operation == "getentropy" else "EINTR"} observer=progress'
                            for operation in ('getrandom', 'getentropy', 'device', 'device-zero')
                            for restart in (0, 1)]
                    if case == 'untrusted':
                        markers += ['RANDOM_MIXED source=virtio bits=0']
                    if case in ('zero', 'ones', 'repeated-word'):
                        markers += ['RANDOM_VIRTIO_REJECTED reason=sample-health bits=0']
                    if case == 'timeout':
                        markers += ['RANDOM_VIRTIO_FAILED reason=timeout quarantined=0']
                    if mode == 'ready-reseed':
                        markers += ['RANDOM_RESEEDED source=virtio bits=256', 'RANDOM_RESEED_CLIENT_PASS']
                    row['missing'] = [marker for marker in markers if marker not in text]
                    completions = [tuple(map(int, match)) for match in re.findall(
                        r'RANDOM_VIRTIO_COMPLETE cookie=(\d+) length=(\d+) accumulated=(\d+) ', text)]
                    if case == 'short' and (len(completions) < 5 or not any(c[1] < 32 for c in completions)
                                             or completions[4][2] != 32):
                        row['missing'].append('five actual short completions totaling 32 bytes')
                    sample = re.findall(rf'RANDOM_SAMPLE linkage={linkage} value=([0-9a-f]{{64}})', text)
                    if ready and (len(sample) != 1 or sample[0] in samples):
                        row['missing'].append('one fresh initialized sample')
                    if not ready and ('RANDOM_READY ' in text or sample):
                        row['missing'].append('untrusted or failed source established readiness')
                    samples.update(sample)
                    row.update(linkage=linkage, case=case, firmware=firmware, transport=transport,
                               trusted=trusted, completions=completions, sample=sample[0] if sample else None,
                               image=fingerprint(image), directory=case_directory.name)
                    row['passed'] = (not row['timed_out'] and row['returncode'] == 1 and
                                     not row['missing'] and not any(marker in text for marker in
                                     ('RANDOM_TEST_FAIL ', 'PANIC:', 'FAULT pid=')))
                    results.append(row)
                    print(json.dumps(row), flush=True)
                    (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError(f'virtio random source failed: {case_directory.name}/{tag}')
    assert inputs == {name: fingerprint(ROOT / name) for name in inputs}, 'source changed during validation'


if __name__ == '__main__':
    main()

"""Verify initialized and early Linux random interfaces in independent guest kernels."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from fetch import ROOT, LOCK

MODES = ('cpu', 'no-cpu', 'rdrand-only', 'trust-off')


def fixture(linkage, mode, reseed=False):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init',
                    'build/random-static', 'build/random-dynamic', 'busybox'], cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    if version != expected:
        raise RuntimeError('random fixture musl differs from the pinned build version')
    files = {name: (0o40755, b'') for name in
             ['bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'root']}
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         ('bin/random-tests', ROOT / 'build' / f'random-{linkage}'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve())]:
        files[name] = (0o100755, source.read_bytes())
    state = 'ready-reseed' if reseed else 'ready' if mode == 'cpu' else 'unready'
    suffix = '-reseed' if reseed else ''
    files['etc/net-test.sh'] = (0o100755, (
        f'#!/bin/sh\nset -e\n/bin/random-tests {state}\necho AXIOM64_TESTS_PASS\n').encode())
    with (ROOT / 'build/rootfs-network.cpio').open('wb') as output:
        for inode, (name, (permissions, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, permissions, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    command = ['python3', 'scripts/image.py', '--test', '--suite', 'network',
               '--output-name', f'axiom64-random-{linkage}-{mode}{suffix}.iso']
    if mode == 'trust-off':
        command += ['--kernel-option', 'random.trust_cpu=off']
    subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def run(linkage, mode, firmware, repetition, timeout, reseed=False):
    suffix = '-reseed' if reseed else ''
    label = f'random-{linkage}-{mode}-{firmware}-{repetition}{suffix}'
    log = ROOT / 'build' / (label + '.log')
    cpu = {'no-cpu': 'max,rdseed=off,rdrand=off', 'rdrand-only': 'max,rdseed=off'}.get(mode, 'max')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', cpu, '-m', '256M', '-nic', 'none',
               '-cdrom', str(ROOT / 'build' / f'axiom64-random-{linkage}-{mode}{suffix}.iso'),
               '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text(errors='replace')
    state = 'ready-reseed' if reseed else 'ready' if mode == 'cpu' else 'unready'
    markers = [f'RANDOM_TEST_PASS linkage={linkage} mode={state}', 'RANDOM_FLAGS_PASS',
               'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}']
    rdseed = int(mode in ('cpu', 'trust-off'))
    markers += [f'RANDOM_SOURCE rdseed={rdseed} trust_cpu={int(mode != "trust-off")}']
    if mode == 'cpu':
        markers += ['RANDOM_READY source=rdseed bits=256', 'RANDOM_READY_PASS',
                    'RANDOM_CONCURRENT_PASS processes=8 samples=distinct']
        if reseed:
            markers += ['RANDOM_RESEEDED source=rdseed bits=256', 'RANDOM_RESEED_CLIENT_PASS']
    else:
        markers += ['RANDOM_UNREADY_PASS'] + [
            f'RANDOM_WAIT_PASS operation={operation} restart={restart} result={"retry" if operation == "getentropy" else "EINTR"} observer=progress'
            for operation in ('getrandom', 'getentropy', 'device', 'device-zero') for restart in (0, 1)]
    missing = [marker for marker in markers if marker not in text]
    sample = re.findall(rf'RANDOM_SAMPLE linkage={linkage} value=([0-9a-f]{{64}})', text)
    if mode == 'cpu' and len(sample) != 1:
        missing.append('exactly one initialized sample')
    if mode != 'cpu' and ('RANDOM_READY ' in text or sample):
        missing.append('uncredited kernel became initialized')
    result = dict(linkage=linkage, mode=mode, firmware=firmware, repetition=repetition, reseed=reseed,
                  returncode=process.returncode, timed_out=timed_out, missing=missing,
                  sample=sample[0] if sample else None, log=log.name,
                  seconds=round(time.monotonic() - started, 3),
                  passed=not timed_out and process.returncode == 1 and not missing and not any(
                      marker in text for marker in ('RANDOM_TEST_FAIL ', 'PANIC:', 'FAULT pid=')))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-5000:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--mode', choices=MODES, nargs='+', default=list(MODES))
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=90)
    parser.add_argument('--reseed', action='store_true', help='add one actual periodic reseed per firmware')
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results, samples = [], set()
    for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
        for mode in args.mode:
            fixture(linkage, mode)
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for repetition in range(2 if mode == 'cpu' else 1):
                    row = run(linkage, mode, firmware, repetition, args.timeout)
                    if row['sample'] is not None:
                        if row['sample'] in samples:
                            row['passed'] = False
                            row['missing'].append('independent kernel repeated initialized sample')
                        samples.add(row['sample'])
                    results.append(row)
                    (ROOT / 'build/random-results.json').write_text(json.dumps(results, indent=2) + '\n')
                    if not row['passed']:
                        raise SystemExit('Guest random interface failed')
    if args.reseed:
        linkage = 'static' if args.linkage == 'both' else args.linkage
        fixture(linkage, 'cpu', reseed=True)
        for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
            row = run(linkage, 'cpu', firmware, 0, args.timeout, reseed=True)
            if row['sample'] in samples:
                row['passed'] = False
                row['missing'].append('periodic-reseed kernel repeated an initialized sample')
            samples.add(row['sample'])
            results.append(row)
            (ROOT / 'build/random-results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not row['passed']:
                raise SystemExit('Guest periodic reseed failed')


if __name__ == '__main__':
    main()

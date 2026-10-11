#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe real OpenSSL initialization, blocked OS reads, signals and entropy release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from build_musl import loader
from fetch import ROOT
from random_administration_test import checked_run, fingerprint, snapshot
from random_crypto.inputs import products, provider
from random_seed_test import image


def guest_run(command, case, mode):
    log = case / 'guest.log'
    started = time.monotonic_ns()
    row = dict(command=command, timed_out=False, passed=False)
    process = None
    try:
        with log.open('wb') as stream:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.PIPE,
                                       stdout=stream, stderr=subprocess.STDOUT)
            deadline = time.monotonic()+60

            def wait(expression):
                while True:
                    data = log.read_bytes()
                    match = re.search(expression, data, re.MULTILINE)
                    if match:
                        return match, data
                    if process.poll() is not None or b'CRYPTO_WAIT_FAIL ' in data:
                        raise RuntimeError('the actual OpenSSL readiness process failed before observation')
                    if time.monotonic() >= deadline:
                        raise TimeoutError('the actual OpenSSL readiness observation expired')
                    time.sleep(.01)

            if mode not in ('ready', 'virtio'):
                match, _ = wait(rb'^CRYPTO_WAIT_START mode='+mode.encode()+rb' pid=(\d+)\r?$')
                pid = match[1]
                _, prefix = wait(rb'^sys pid='+pid+rb' nr=318 a=[0-9a-f]+ b=[0-9a-f]+ c=0\r?\n'
                                 rb'sys result=-4096\r?$')
                row['blocked_syscall'] = dict(pid=int(pid), prefix_bytes=len(prefix),
                                             prefix_sha256=hashlib.sha256(prefix).hexdigest(),
                                             observed_ns=time.monotonic_ns())
                process.stdin.write(b'B')
                process.stdin.flush()
                sent = time.monotonic_ns()
                _, prefix = wait(rb'^CRYPTO_WAIT_BLOCKED mode='+mode.encode()+rb' pid='+pid+
                                 rb' elapsed_ns=\d+ credit=0\r?$')
                observed = time.monotonic_ns()
                row['blocking_barrier'] = dict(sent_ns=sent, observed_ns=observed,
                                              elapsed_ns=observed-sent, prefix_bytes=len(prefix),
                                              prefix_sha256=hashlib.sha256(prefix).hexdigest())
                if observed-sent < 500_000_000:
                    raise RuntimeError('the native observer did not measure the required blocking interval')
                if mode == 'administrative':
                    seed = os.getrandom(32)
                    if len(seed) != 32:
                        raise RuntimeError('native OS entropy delivery was short')
                    process.stdin.write(seed.hex().encode())
                    process.stdin.flush()
                    row['entropy_delivery'] = dict(source='native-linux-getrandom', bytes=32,
                                                    sha256=hashlib.sha256(seed).hexdigest(),
                                                    sent_ns=time.monotonic_ns())
            process.wait(timeout=max(.01, deadline-time.monotonic()))
        row.update(returncode=process.returncode, elapsed_ns=time.monotonic_ns()-started,
                   log=log.name, log_input=fingerprint(log))
        return row, log.read_text()
    except BaseException as error:
        row.update(error=repr(error), timed_out=isinstance(error, (TimeoutError, subprocess.TimeoutExpired)))
        raise
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if process is not None:
            process.stdin.close()
        row.update(returncode=process.returncode if process else None, elapsed_ns=time.monotonic_ns()-started)
        if log.exists():
            row['log_input'] = fingerprint(log)
        (case / 'process.json').write_text(json.dumps(row, indent=2)+'\n')


def observe(row, text, mode, native):
    starts = re.findall(r'^CRYPTO_WAIT_START mode='+mode+r' pid=(\d+)$', text, re.MULTILINE)
    if (len(starts) != 1 or 'CRYPTO_WAIT_FAIL ' in text or
            text.count('CRYPTO_WAIT_PASS mode='+mode+' ') != 1):
        raise RuntimeError('the actual cryptographic readiness client failed')
    pid = starts[0]
    if mode not in ('ready', 'virtio'):
        blocks = re.findall(r'^CRYPTO_WAIT_BLOCKED mode='+mode+r' pid='+pid+
                            r' elapsed_ns=(\d+) credit=0$', text, re.MULTILINE)
        if len(blocks) != 1 or not 500_000_000 <= int(blocks[0]) < 2_000_000_000:
            raise RuntimeError('the real initialization blocking observation is missing')
        if not re.search(r'^sys pid='+pid+r' nr=318 a=[0-9a-f]+ b=[0-9a-f]+ c=0\n'
                         r'sys result=-4096$', text, re.MULTILINE):
            raise RuntimeError('the actual OpenSSL process did not block in Linux getrandom')
        row['blocked_ns'] = int(blocks[0])
    outputs = re.findall(r'^CRYPTO_WAIT_OUTPUT mode='+mode+r' bytes=32 hex=([0-9a-f]{64})$',
                         text, re.MULTILINE)
    if mode in ('ready', 'virtio', 'administrative'):
        if len(outputs) != 1 or 'CRYPTO_WAIT_PASS mode='+mode+' status=0 credit=256' not in text:
            raise RuntimeError('the initialized OpenSSL output or credit is incomplete')
        row['output_sha256'] = hashlib.sha256(bytes.fromhex(outputs[0])).hexdigest()
    elif outputs or 'CRYPTO_WAIT_PASS mode='+mode+' signal=15 credit=0' not in text:
        raise RuntimeError('the uninitialized OpenSSL process returned data or the wrong signal')
    if not native and ('AXIOM64_TESTS_PASS\n' not in text or 'AXIOM64_EXIT status=0\n' not in text):
        raise RuntimeError('the guest did not finish its readiness checks')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--provider', choices=('build', 'runtime', 'all'), default='all')
    parser.add_argument('--linkage', choices=('native', 'static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--mode', choices=('ready', 'absent', 'untrusted', 'virtio', 'administrative'), nargs='+')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-crypto-wait-results')
    args = parser.parse_args()
    if args.linkage == 'native' and not args.native:
        parser.error('native libc requires --native')
    modes = args.mode or (['ready'] if args.native else ['ready', 'absent', 'untrusted', 'virtio', 'administrative'])
    if args.native and modes != ['ready']:
        parser.error('the already initialized native Linux CRNG cannot test early boot')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    linkages = ('native', 'static', 'dynamic') if args.native and args.linkage == 'both' else (
               ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,))
    profiles = ('build',) if args.native else (('build', 'runtime') if args.provider == 'all' else (args.provider,))
    providers = {name: provider(name) for name in profiles}
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    *(f'build/{name}-{linkage}' for linkage in linkages for name in
                      (('crypto-wait',) if args.native else
                       ('crypto-wait', 'random', 'random-seed', 'random-seed-probe')))], cwd=ROOT, check=True)
    inputs = snapshot(out)
    for path in [ROOT / 'scripts/random_crypto_wait_test.py', ROOT / 'userspace/tests/random/crypto_wait.c',
                 ROOT / 'scripts/random_entropy_peer.py', ROOT / 'scripts/random_seed_test.py',
                 ROOT / 'scripts/image.py', *(ROOT / 'scripts/random_crypto').glob('*.py')]:
        inputs[str(path.relative_to(ROOT))] = fingerprint(path)
    (out / 'source-inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    for name, (directory, _) in providers.items():
        shutil.copyfile(directory / 'manifest.json', out / ('openssl-'+name+'-manifest.json'))
    results = []
    for linkage in linkages:
        name = 'build' if args.native or linkage == 'static' else 'runtime'
        if args.provider != 'all' and not args.native:
            name = args.provider
        directory, manifest = providers[name]
        for mode in modes:
            for firmware in (('native',) if args.native else
                             (('bios', 'uefi') if args.firmware == 'both' else (args.firmware,))):
                for transport in (('none',) if args.native or mode in ('ready', 'absent', 'administrative') else
                                  (('modern', 'legacy') if args.transport == 'both' else (args.transport,))):
                    case = out / '-'.join((linkage, mode, firmware, transport))
                    case.mkdir()
                    row = dict(linkage=linkage, mode=mode, firmware=firmware, transport=transport,
                               openssl_identity=manifest['identity'], passed=False)
                    try:
                        if args.native:
                            client = ROOT / ('build/crypto-wait-'+linkage)
                            shutil.copyfile(client, case / 'crypto-wait')
                            openssl = directory / 'static/stage/usr/bin/openssl'
                            shutil.copyfile(openssl, case / 'openssl')
                            command = [str(case / 'crypto-wait'), 'ready', str(case / 'openssl'), str(case / 'random.bin')]
                            if linkage == 'dynamic':
                                command.insert(0, str(loader()))
                            row.update(client=fingerprint(case / 'crypto-wait'), openssl=fingerprint(case / 'openssl'))
                        else:
                            extras = products(directory, linkage)
                            extras['bin/crypto-wait'] = ROOT / ('build/crypto-wait-'+linkage)
                            options = () if mode == 'ready' else ('random.trust_cpu=off',)
                            if mode == 'virtio':
                                options += ('random.trust_virtio=on',)
                            if mode == 'untrusted':
                                options += ('random.trust_virtio=off',)
                            iso = image(case, linkage, 'crypto-wait-'+mode,
                                        command='/bin/crypto-wait '+mode+' /usr/bin/openssl /tmp/random.bin',
                                        extra_products=extras, kernel_options=options, trace=True)
                            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu',
                                       'max' if mode == 'ready' else 'max,rdseed=off,rdrand=off', '-m', '512M',
                                       '-nic', 'none', '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio',
                                       '-monitor', 'none', '-no-reboot', '-device',
                                       'isa-debug-exit,iobase=0xf4,iosize=0x04']
                            if mode in ('virtio', 'untrusted'):
                                command += ['-object', 'rng-random,id=entropy,filename=/dev/urandom']
                                command += ['-device', 'virtio-rng-pci,rng=entropy,' +
                                            ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
                            if firmware == 'uefi':
                                variables = case / 'VARS.fd'
                                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                            '-drive', 'if=pflash,format=raw,file='+str(variables)]
                                row['firmware_inputs'] = {path: fingerprint(Path('/usr/share/OVMF') / path)
                                                         for path in ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd')}
                            row['image'] = fingerprint(iso)
                        process, text = checked_run(command, case / 'native.log', 30) if args.native else guest_run(command, case, mode)
                        row.update(process)
                        if row['returncode'] != (0 if args.native else 1) or row['timed_out']:
                            raise RuntimeError('the actual cryptographic readiness process failed')
                        observe(row, text, mode, args.native)
                        if mode == 'virtio' and 'RANDOM_READY source=virtio bits=256\n' not in text:
                            raise RuntimeError('the trusted virtio source did not initialize the generator')
                        if mode == 'administrative' and 'CRYPTO_ADMIN_INITIALIZED source=native-os credited_bits=256\n' not in text:
                            raise RuntimeError('the administrative source did not initialize the generator')
                        if mode != 'ready' and 'RANDOM_SOURCE rdseed=0 trust_cpu=0\n' not in text:
                            raise RuntimeError('the guest CPU entropy exclusion is missing')
                        if mode == 'untrusted' and f'RANDOM_VIRTIO_SOURCE transport={transport} trusted=0' not in text:
                            raise RuntimeError('untrusted input used the wrong policy')
                        row['passed'] = True
                    except BaseException as error:
                        row['error'] = repr(error)
                        raise
                    finally:
                        (case / 'result.json').write_text(json.dumps(row, indent=2)+'\n')
                        results.append(row)
                        (out / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
                    print(json.dumps(dict(case=case.name, passed=True)), flush=True)
    if inputs != {path: fingerprint(ROOT / path) for path in inputs}:
        raise RuntimeError('the real cryptographic readiness sources changed')


if __name__ == '__main__':
    main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe all three libc/linkage profiles in fresh native Linux namespaces."""
import argparse
import gzip
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time
import zipfile

from build_musl import loader
from compile_uapi_client import audit_compile
from fetch import ROOT
from ipv4_lifetimes import native_clock
from ipv4_lifetimes.reader import decode, require, verify as read
from ipv4_source_route.artifacts import compilation, providers
from ipv4_source_route.native import configuration
from tcp6.inputs import digest, freeze, write

PROFILES = ('native', 'static', 'dynamic')
CLIENT = 'userspace/tests/net/ipv4/address_lifetimes.c'


def worker(directory, profile, parent_namespace):
    require(os.geteuid() == 0 and profile in PROFILES and
            Path('/proc/self/ns/net').stat().st_ino != parent_namespace,
            'actual root worker owns an isolated native network namespace')
    directory.mkdir(exist_ok=False)
    for interface in ('eth0', 'eth1'):
        for arguments in (('link', 'add', interface, 'type', 'dummy'), ('link', 'set', interface, 'up')):
            subprocess.run(['ip', *arguments], check=True, stdin=subprocess.DEVNULL)
    links = subprocess.check_output(['ip', '-j', 'address', 'show'], text=True)
    (directory / 'links-before.json').write_text(links)
    kernel = platform.release()
    path = Path('/boot/config-' + kernel)
    data = path.read_bytes() if path.is_file() else gzip.decompress(Path('/proc/config.gz').read_bytes())
    (directory / 'kernel.config').write_bytes(data)
    hz = configuration(data)
    anchors = [native_clock.capture(socket.if_nametoindex('eth0'), 0)]
    program = ROOT / 'build' / ('ipv4-address-lifetimes-' + profile)
    compiled = audit_compile(program, ROOT)
    shutil.copy2(program, directory / 'program')
    write(directory / 'program.inputs.json', compiled)
    interpreter = loader('build').resolve() if profile == 'dynamic' else None
    command = ([str(interpreter)] if interpreter else []) + [str(program), 'eth0', 'eth1']
    write(directory / 'command.json', command)
    (directory / 'runtime').mkdir()
    began = time.monotonic_ns()
    timed_out = False
    with (directory / 'client.log').open('xb') as log:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 5
            while True:
                require(process.poll() is None, 'native client remains alive for actual provider observation')
                if (directory / 'client.log').stat().st_size:
                    break
                require(time.monotonic() < deadline, 'bounded real native client readiness')
                time.sleep(0.01)
            maps = Path('/proc', str(process.pid), 'maps').read_text()
            (directory / 'maps.txt').write_text(maps)
            executable = str(Path('/proc', str(process.pid), 'exe').resolve())
            require(executable == str(interpreter if interpreter else program.resolve()),
                    'actual running native executable or selected musl loader')
            retained = {}
            paths = {}
            for line in maps.splitlines():
                fields = line.split(None, 5)
                if len(fields) == 6 and fields[5].startswith('/'):
                    paths[fields[5]] = int(fields[4])
            require(str(program) in paths, 'actual target client is mapped before runtime capture')
            for source, inode in sorted(paths.items()):
                path = Path(source)
                if source == str(program) or (profile == 'static'):
                    continue
                require(path.is_file() and path.stat().st_ino == inode, 'actual mapped provider inode')
                name = 'runtime/' + ('ld-musl-x86_64.so.1' if profile == 'dynamic' else str(len(retained)) + '-' + path.name)
                shutil.copy2(path, directory / name)
                retained[name] = dict(source=source, inode=inode, sha256=digest(directory / name))
            write(directory / 'runtime.json', dict(providers=retained, executable=executable,
                  client_pid=process.pid, affinity=sorted(os.sched_getaffinity(process.pid))))
            try:
                process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
    receipt = dict(profile=profile, returncode=process.returncode, timed_out=timed_out,
                   elapsed_ns=time.monotonic_ns() - began, kernel=kernel, hz=hz,
                   kernel_config_sha256=digest(directory / 'kernel.config'), command_sha256=digest(directory / 'command.json'),
                   log_sha256=digest(directory / 'client.log'), parent_namespace=parent_namespace,
                   namespace=Path('/proc/self/ns/net').stat().st_ino)
    anchors.append(native_clock.capture(socket.if_nametoindex('eth0'), 1))
    write(directory / 'kernel-clock.json', anchors)
    write(directory / 'process.json', receipt)
    require(process.returncode == 0 and not timed_out, 'native client syscall assertions pass')
    epoch = native_clock.verify(directory / 'kernel-clock.json', directory / 'client.log')
    receipt['observations'] = read(directory / 'client.log', stamp_epoch=epoch)
    require(platform.release() == kernel, 'native kernel remains unchanged')
    write(directory / 'completed.json', receipt)
    return receipt


def verify(directory):
    directory = Path(directory).resolve()
    index = decode((directory / 'completed.json').read_text())
    require(index['passed'] is True and index['schema'] == 1 and index['profiles'] == list(PROFILES),
            'all three native libc and linkage profiles')
    inputs = decode((directory / 'source/source-inputs.json').read_text())
    require(digest(directory / 'source/source.zip') == index['source']['source_zip_sha256'] and
            digest(directory / 'source/source-inputs.json') == index['source']['source_inputs_sha256'],
            'exact native source archive and complete inventory')
    import hashlib
    with zipfile.ZipFile(directory / 'source/source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) == index['source']['files'] and set(archive.namelist()) == set(inputs),
                'complete unique native source members')
        for name, fingerprint in inputs.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == fingerprint, 'every retained native source byte')
    for name in ('native.py', 'native_clock.py', 'reader.py'):
        require(inputs['scripts/ipv4_lifetimes/' + name] == digest(Path(__file__).with_name(name)),
                'same original native producer and observation readers')
    kernels = set()
    proofs = []
    for profile in PROFILES:
        case = directory / profile
        receipt = decode((case / 'completed.json').read_text())
        require(receipt['profile'] == profile and receipt['returncode'] == 0 and receipt['timed_out'] is False and
                receipt['log_sha256'] == digest(case / 'client.log') and
                receipt['command_sha256'] == digest(case / 'command.json') and receipt['elapsed_ns'] >= 18_000_000_000 and
                type(receipt['namespace']) is int and receipt['namespace'] != receipt['parent_namespace'],
                'actual completed isolated native process and elapsed observation')
        hz = configuration((case / 'kernel.config').read_bytes())
        require(receipt['hz'] == hz and receipt['kernel_config_sha256'] == digest(case / 'kernel.config'),
                'actual native kernel timer configuration')
        kernels.add((receipt['kernel'], hz, receipt['kernel_config_sha256']))
        compilation(case, inputs, profile, CLIENT)
        command = decode((case / 'command.json').read_text())
        require(type(command) is list and len(command) == (4 if profile == 'dynamic' else 3) and
                command[-2:] == ['eth0', 'eth1'] and Path(command[-3]).name == 'ipv4-address-lifetimes-' + profile,
                'actual native command selects both fixture interfaces')
        runtime = decode((case / 'runtime.json').read_text())
        require(type(runtime['client_pid']) is int and runtime['client_pid'] > 0 and runtime['affinity'],
                'actual observed client process and CPU affinity')
        selected_loader = command[0] if profile == 'dynamic' else None
        providers(case, runtime, (case / 'maps.txt').read_text(), profile,
                  set(command[:-2]), selected_loader)
        epoch = native_clock.verify(case / 'kernel-clock.json', case / 'client.log')
        proof = read(case / 'client.log', stamp_epoch=epoch)
        require(proof == receipt['observations'], 'exact independent native lifetime observations')
        proofs.append(dict(profile=profile, observations=proof))
    require(len(kernels) == 1, 'one actual native kernel and timer policy throughout the cohort')
    return dict(passed=True, profiles=3, interfaces_per_profile=2, requests=198,
                kernel=next(iter(kernels))[0], observations=proofs, wire_or_guest_or_hosted_acceptance=False)


def produce(directory):
    require(os.geteuid() == 0 and 'GH_TOKEN' not in os.environ, 'credential-free actual root native controller')
    directory = Path(directory).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'designated native output directory')
    directory.mkdir(exist_ok=False)
    subprocess.run(['make', '-j2', *['build/ipv4-address-lifetimes-' + profile for profile in PROFILES]], cwd=ROOT, check=True)
    (directory / 'source').mkdir()
    source = freeze(directory / 'source')
    inputs = decode((directory / 'source/source-inputs.json').read_text())
    parent_namespace = Path('/proc/self/ns/net').stat().st_ino
    failures = []
    for profile in PROFILES:
        command = ['unshare', '-n', '--', sys.executable, '-B', '-m', 'ipv4_lifetimes.native',
                   str(directory / profile), '--worker', '--profile', profile, '--parent-namespace', str(parent_namespace)]
        with (directory / (profile + '-worker.log')).open('xb') as log:
            result = subprocess.run(command, cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'scripts')),
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        write(directory / (profile + '-worker.json'), dict(returncode=result.returncode, log_sha256=digest(directory / (profile + '-worker.log'))))
        if result.returncode:
            failures.append(profile)
        print('IPV4_LIFETIME_NATIVE_RESULT ' + profile + ' status=' + str(result.returncode), flush=True)
    require(not failures, 'native profiles failed without retry: ' + ','.join(failures))
    require(all(digest(ROOT / name) == value for name, value in inputs.items()), 'unchanged complete source during native observations')
    write(directory / 'completed.json', dict(passed=True, schema=1, profiles=list(PROFILES), source=source))
    proof = verify(directory)
    write(directory / 'verified.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--produce', action='store_true')
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--profile', choices=PROFILES)
    parser.add_argument('--parent-namespace', type=int)
    args = parser.parse_args()
    if args.worker:
        require(args.profile is not None and args.parent_namespace is not None, 'explicit isolated worker inputs')
        proof = worker(args.directory.resolve(), args.profile, args.parent_namespace)
    else:
        proof = produce(args.directory) if args.produce else verify(args.directory)
    print(json.dumps(proof), flush=True)


if __name__ == '__main__':
    main()

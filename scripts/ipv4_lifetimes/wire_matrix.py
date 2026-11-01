# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture three native linkages and eight two-adapter guest profiles without retrying failures."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import subprocess
import sys
import threading
import time

from ci.paired_network import stop
from compile_uapi_client import audit_compile
from fetch import ROOT
from ipv4_lifetimes.reader import decode, require
from ipv4_lifetimes.wire_evidence import (CLOCK_ERRORS, clock_qualification, observations, ordinary_tree,
                                         read_artifacts, source, verify as read)
from ipv4_lifetimes.wire_worker import prepare
from tcp6.inputs import digest, freeze, source_names, write

PROCESSES = {}
PROCESS_LOCK = threading.Lock()
STOPPING = threading.Event()


def stop_workers():
    STOPPING.set()
    with PROCESS_LOCK:
        processes = list(PROCESSES.values())
        PROCESSES.clear()
    for process in processes:
        stop(process)


def specifications():
    return ([dict(path='native-' + profile, mode='native', profile=profile, firmware='bios', transport='modern')
             for profile in ('native', 'static', 'dynamic')] +
            [dict(path=f'guest-{profile}-{firmware}-{transport}', mode='guest', profile=profile,
                  firmware=firmware, transport=transport)
             for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')])


def products(directory, index):
    ordinary_tree(directory)
    require(index['schema'] == 1 and type(index['schema']) is int and index['profiles'] == specifications() and
            index['workers'] == 2, 'fixed complete eleven-profile lifetime wire inventory')
    original = PurePosixPath(index['original_directory'])
    require(original.is_absolute() and '..' not in original.parts and str(original) == index['original_directory'],
            'canonical original matrix directory')
    inputs = source(directory, index['source'])
    require(set(index['programs']) == {'native', 'static', 'dynamic'}, 'all three actual client linkages')
    for name, expected in index['firmware'].items():
        require(name in ('OVMF_CODE.fd', 'OVMF_VARS.original.fd') and
                dict(bytes=(directory / name).stat().st_size, sha256=digest(directory / name)) == expected,
                'exact common firmware and original variable-store bytes')
    require(set(index['firmware']) == {'OVMF_CODE.fd', 'OVMF_VARS.original.fd'}, 'both common firmware inputs')
    for profile in ('static', 'dynamic'):
        saved = decode((directory / profile / 'products.json').read_text())
        require(saved['kernel.elf']['sha256'] == index['kernel_sha256'] and
                saved['bin/ipv4-lifetime-wire']['sha256'] == index['programs'][profile], 'two shared images use the common kernel and clients')
    return inputs


def identity(directory, index, spec):
    case = directory / spec['path']
    captured = decode((case / 'captured.json').read_text())
    worker = decode((directory / (spec['path'] + '.worker.json')).read_text())
    require(worker['status'] == 'completed' and type(worker['returncode']) is int and worker['returncode'] == 0 and
            worker['timed_out'] is False and type(worker['elapsed_ns']) is int and
            worker['elapsed_ns'] >= captured['elapsed_ns'] >= 60_000_000_000 and
            worker['log_sha256'] == digest(directory / (spec['path'] + '.worker.log')), 'actual completed isolated worker')
    original = PurePosixPath(index['original_directory'])
    require(all(captured[key] == spec[key] for key in ('mode', 'profile', 'firmware', 'transport')) and
            captured['source'] == index['source'] and captured['shared_directory'] == str(original) and
            captured['original_directory'] == str(original / spec['path']) and
            digest(case / 'program') == index['programs'][spec['profile']], 'one original public source and client per linkage')
    command = worker['command']
    prefix = ['unshare', '-n', '--'] if spec['mode'] == 'native' else []
    require(type(command) is list and len(command) > len(prefix) and command[:len(prefix)] == prefix,
            'actual namespace wrapper for the requested worker')
    interpreter = command[len(prefix)]
    require(type(interpreter) is str and PurePosixPath(interpreter).is_absolute() and
            PurePosixPath(interpreter).name.startswith('python3'), 'original Python worker interpreter')
    expected = [*prefix, interpreter, '-B', '-m', 'ipv4_lifetimes.wire_worker', str(original / spec['path']),
                '--mode', spec['mode'], '--profile', spec['profile'], '--firmware', spec['firmware'],
                '--transport', spec['transport'], '--shared', str(original)]
    if spec['mode'] == 'native':
        host = decode((case / 'native.json').read_text())
        expected += ['--parent-namespace', str(host['parent_namespace'])]
        require(captured['firmware_inputs'] == {}, 'native worker has no emulated firmware inputs')
    else:
        require(captured['firmware_inputs'] == (index['firmware'] if spec['firmware'] == 'uefi' else {}),
                'actual requested common firmware inputs')
    require(command == expected, 'every original worker command argument and shared fixture path')
    return captured


def inspect(directory):
    directory = Path(directory).resolve()
    ordinary_tree(directory)
    index = decode((directory / 'inputs.json').read_text())
    products(directory, index)
    matrix = decode((directory / 'matrix.json').read_text())
    require(matrix['terminal'] is True and type(matrix['passed']) is bool and matrix['profiles'] == specifications() and
            matrix['workers'] == 2 and set(matrix['results']) == {spec['path'] for spec in specifications()},
            'all eleven original workers are terminal with the complete profile inventory')
    proofs, qualifications, kernels = {}, {}, set()
    for spec in specifications():
        case = directory / spec['path']
        captured = identity(directory, index, spec)
        if spec['mode'] == 'native':
            host = decode((case / 'native.json').read_text())
            kernels.add((host['kernel'], host['kernel_config_sha256']))
        value = read_artifacts(case)
        proof = observations(value)
        qualification = dict(passed=True, proof=proof)
        try:
            clock_qualification(value)
        except ValueError as error:
            require(str(error) in CLOCK_ERRORS, 'only an explicit original clock discontinuity is inspectable')
            qualification = dict(passed=False, error=str(error), exception='ValueError')
        require(matrix['results'][spec['path']] == qualification, 'same independently reopened profile qualification')
        qualifications[spec['path']] = qualification
        proofs[spec['path']] = proof
    require(len(kernels) == 1, 'one actual native kernel throughout all three libc profiles')
    passed = all(value['passed'] for value in qualifications.values())
    require(matrix['passed'] is passed, 'recorded aggregate matches every actual clock qualification')
    return dict(passed=passed, profiles=11, native_profiles=3, guest_profiles=8, cases_per_profile=24,
                adapters=2, transports=3, survival_states=4, workers=2, immutable_guest_images=2,
                clocks_adjusted=False, full_feature_acceptance=False, results=proofs, qualifications=qualifications)


def verify(directory):
    proof = inspect(directory)
    require(proof['passed'] is True, 'all eleven original workers and strict readers passed')
    return proof


def worker(directory, spec):
    case = directory / spec['path']
    command = [sys.executable, '-B', '-m', 'ipv4_lifetimes.wire_worker', str(case), '--mode', spec['mode'],
               '--profile', spec['profile'], '--firmware', spec['firmware'], '--transport', spec['transport'], '--shared', str(directory)]
    if spec['mode'] == 'native':
        command += ['--parent-namespace', str(Path('/proc/self/ns/net').stat().st_ino)]
        command = ['unshare', '-n', '--', *command]
    began = time.monotonic_ns()
    write(directory / (spec['path'] + '.worker.json'), dict(status='starting', command=command))
    with (directory / (spec['path'] + '.worker.log')).open('xb') as stream:
        with PROCESS_LOCK:
            require(not STOPPING.is_set(), 'cancelled matrix cannot start another capture')
            process = subprocess.Popen(command, cwd=ROOT, env=dict(os.environ, PYTHONPATH=str(ROOT / 'scripts')),
                                       stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
            PROCESSES[spec['path']] = process
        timed_out = False
        try:
            process.wait(timeout=340)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        finally:
            with PROCESS_LOCK:
                owned = PROCESSES.pop(spec['path'], None)
            if owned is not None:
                stop(owned)
    write(directory / (spec['path'] + '.worker.json'), dict(status='completed', command=command,
          returncode=process.returncode, timed_out=timed_out, elapsed_ns=time.monotonic_ns() - began,
          log_sha256=digest(directory / (spec['path'] + '.worker.log'))))
    require(not timed_out and process.returncode == 0, 'actual full campaign worker: ' + spec['path'])
    return dict(passed=True, proof=read(case))


def produce(directory):
    require(os.geteuid() == 0 and 'GH_TOKEN' not in os.environ, 'credential-free actual root owns network namespaces')
    directory = Path(directory).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'designated ignored matrix output')
    directory.mkdir(exist_ok=False)
    STOPPING.clear()
    with (directory / 'build.log').open('xb') as stream:
        subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                        *['build/ipv4-lifetime-wire-' + profile for profile in ('native', 'static', 'dynamic')]],
                       cwd=ROOT, check=True, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT)
    (directory / 'source').mkdir()
    snapshot = freeze(directory / 'source')
    inventory = decode((directory / 'source/source-inputs.json').read_text())
    firmware = {}
    for original, name in (('/usr/share/OVMF/OVMF_CODE_4M.fd', 'OVMF_CODE.fd'),
                            ('/usr/share/OVMF/OVMF_VARS_4M.fd', 'OVMF_VARS.original.fd')):
        shutil.copy2(original, directory / name)
        firmware[name] = dict(bytes=(directory / name).stat().st_size, sha256=digest(directory / name))
    programs = {}
    for profile in ('native', 'static', 'dynamic'):
        program = ROOT / 'build' / ('ipv4-lifetime-wire-' + profile)
        compiled = audit_compile(program, ROOT)
        programs[profile] = digest(program)
        if profile != 'native':
            base = directory / profile
            base.mkdir()
            prepare(base, profile, program, compiled)
    index = dict(schema=1, original_directory=str(directory), source=snapshot, programs=programs,
                 kernel_sha256=digest(ROOT / 'build/axiom64.elf'), firmware=firmware, profiles=specifications(), workers=2)
    write(directory / 'inputs.json', index)
    products(directory, index)
    results = {}
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        running = {pool.submit(worker, directory, spec): spec for spec in specifications()}
        for future in as_completed(running):
            spec = running[future]
            try:
                results[spec['path']] = future.result()
            except Exception as error:
                results[spec['path']] = dict(passed=False, error=str(error), exception=type(error).__name__)
            write(directory / 'matrix.json', dict(terminal=False, passed=False, workers=2, profiles=specifications(), results=results))
            print(json.dumps(dict(profile=spec['path'], **results[spec['path']])), flush=True)
    finally:
        stop_workers()
        pool.shutdown(wait=True, cancel_futures=True)
    names, _ = source_names()
    require(set(names) == set(inventory) and all(digest(ROOT / name) == value for name, value in inventory.items()),
            'public source remains unchanged throughout the complete matrix')
    write(directory / 'matrix.json', dict(terminal=True, passed=all(value['passed'] for value in results.values()),
                                         workers=2, profiles=specifications(), results=results))
    return verify(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--produce', action='store_true')
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt('lifetime wire matrix interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    print(json.dumps(produce(args.directory) if args.produce else verify(args.directory)), flush=True)


if __name__ == '__main__':
    main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Produce and independently reopen every source-route linkage and guest profile."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time

from account_store_guest import fixture
from compile_uapi_client import audit_compile, sources
from fetch import ROOT
from ipv4_source_route import applications, model, queues, native as native_observer
from ipv4_source_route.controls import decode, require
from ipv4_source_route.corpus import cases, checksum
from ipv4_source_route.wire_evidence import snapshot, verify as verify_case
from tcp6.inputs import digest, freeze, source_names, write
from ci.paired_network import stop

PHASES = ('packets', 'applications', 'queues')
BOUND = ('applications.py', 'corpus.py', 'packets.json', 'packets.py', 'queues.json', 'queues.py',
         'worker.py', 'matrix.py', 'model.py', 'wire_evidence.py', 'wire_controls.py', 'faults.py', 'protected.py', 'window.py', 'native.py', 'artifacts.py')


def specifications():
    result = []
    for phase in PHASES:
        for profile in ('native', 'static', 'dynamic'):
            result.append(dict(path=f'{phase}-native-{profile}', phase=phase, mode='native',
                               profile=profile, firmware='bios', transport='modern'))
        for profile in ('static', 'dynamic'):
            for firmware in ('bios', 'uefi'):
                for transport in ('modern', 'legacy'):
                    result.append(dict(path=f'{phase}-guest-{profile}-{firmware}-{transport}', phase=phase,
                                       mode='guest', profile=profile, firmware=firmware, transport=transport))
    return result


def definition(phase):
    return {'packets': cases, 'applications': applications.definitions, 'queues': queues.definitions}[phase]()


def observe(directory, phase):
    if phase == 'packets':
        return verify_case(directory)
    module = applications if phase == 'applications' else queues
    observer = queues.reader(directory) if phase == 'queues' else module.observations
    return verify_case(directory, definitions=module.definitions(), observe=observer)


def native_wire(directory):
    native_observer.bounds(directory)
    native_observer.ingress(directory)
    offloads = decode((directory / 'offloads.json').read_text())
    require(set(offloads) == {'eth0', 'peer0', 'eth1', 'peer1'}, 'both ends of both native adapters')
    for value in offloads.values():
        require(set(value) == {'before', 'after'} and all(field + ': off' in value['after'] for field in
                ('tx-checksumming', 'tcp-segmentation-offload', 'generic-segmentation-offload', 'generic-receive-offload')),
                'actual complete software-checksummed native packets')
    statistics = decode((directory / 'packet-statistics.json').read_text())
    require(set(statistics) == {'0', '1'} and all(set(value) == {'packets', 'drops'} and
            type(value['packets']) is int and value['packets'] > 0 and type(value['drops']) is int and value['drops'] == 0
            for value in statistics.values()), 'zero native capture drops on both adapters')
    auxiliary_binding(decode((directory / 'wire.json').read_text()), decode((directory / 'auxiliary.json').read_text()))
    auxiliary_binding(decode((directory / 'boot-wire.json').read_text()), decode((directory / 'boot-auxiliary.json').read_text()))


def auxiliary_binding(wire, auxiliary):
    received = [number for number, value in enumerate(wire) if value['direction'] == 'output']
    require([value['wire_offset'] for value in auxiliary] == received, 'all original native packet auxiliary metadata')
    for value in auxiliary:
        original = wire[value['wire_offset']]
        require(value['case'] == original['case'] and value['index'] == original['index'] and
                value['frame_sha256'] == __import__('hashlib').sha256(bytes.fromhex(original['frame'])).hexdigest() and
                len(value['controls']) == 1, 'exact native packet auxiliary binding')
        control = value['controls'][0]
        data = bytes.fromhex(control['data'])
        require(control['level'] == 263 and control['kind'] == 8 and len(data) == 20 and
                not struct.unpack_from('I', data)[0] & 8, 'native packet checksum is complete before comparison')


def boot_traffic(directory, native):
    records = decode((directory / 'boot-wire.json').read_text())
    first = decode((directory / 'results.json').read_text())[0]['input_began_ns']
    previous = -1
    require(type(records) is list, 'retained original startup Ethernet records')
    for value in records:
        require(set(value) == {'case', 'index', 'direction', 'frame', 'monotonic_ns', 'realtime_ns', 'packet_type'} and
                type(value['case']) is int and value['case'] == -1 and type(value['index']) is int and
                value['index'] in (0, 1) and value['direction'] == 'output' and
                type(value['monotonic_ns']) is int and previous <= value['monotonic_ns'] <= first and
                type(value['realtime_ns']) is int and 0 <= value['realtime_ns'] < 1 << 63,
                'ordered actual pre-case startup receipts')
        previous = value['monotonic_ns']
        require(value['packet_type'] is None or (native and type(value['packet_type']) is int and
                0 <= value['packet_type'] <= 4), 'actual startup packet-socket metadata')
        frame = bytes.fromhex(value['frame'])
        require(len(frame) >= 62 and frame[6:12] == bytes((2, 0, 0, 0, 0, value['index'] + 1)) and
                frame[12:14] == b'\x86\xdd' and frame[14] >> 4 == 6 and
                int.from_bytes(frame[18:20], 'big') == len(frame) - 54 and
                frame[:6] == b'\x33\x33' + frame[50:54], 'complete actual multicast IPv6 startup packet')
        next_header, start = frame[20], 54
        if next_header == 0:
            require(start + 8 <= len(frame), 'complete startup hop-by-hop header')
            next_header, start = frame[start], start + (frame[start + 1] + 1) * 8
        require(next_header == 58 and start + 8 <= len(frame), 'actual ICMPv6 startup payload')
        payload = frame[start:]
        pseudo = frame[22:54] + len(payload).to_bytes(4, 'big') + bytes((0, 0, 0, 58))
        require(payload[0] in (130, 131, 132, 133, 135, 143) and checksum(pseudo + payload) == 0,
                'complete independently checksummed neighbor or multicast startup traffic')


def boot(directory, spec, firmware):
    command = decode((directory / 'command.json').read_text())
    text = (directory / 'client.log').read_text().replace('\r\n', '\n')
    lines = text.splitlines()
    require(lines.count('Firmware: ' + spec['firmware'].upper()) == 1 and
            len([line for line in lines if line.startswith('Firmware: ')]) == 1,
            'actual requested boot firmware')
    require([line for line in lines if line.startswith('NET_DEVICE ')] == [
            f'NET_DEVICE index={n + 1} name=eth{n} mtu=1500 carrier=1 mac=2:0:0:0:0:{n + 1}' for n in (0, 1)] and
            len([line for line in lines if line.startswith('virtio-net: ')]) == 1 and
            re.search(r'^virtio-net: index=1 transport=' + spec['transport'] + r' rx=\d+ tx=\d+ features=[0-9a-f]+$', text, re.M) and
            lines.count('e1000: index=2 model=82540EM rx=64 tx=64') == 1, 'actual two-adapter driver and transport inventory')
    require(command[command.index('-machine') + 1] == 'pc' and command[command.index('-cpu') + 1] == 'max' and
            command[command.index('-m') + 1] == '256M', 'original machine CPU and memory configuration')
    devices = [command[n + 1] for n, value in enumerate(command) if value == '-device']
    virtio = 'virtio-net-pci,' + ('disable-legacy=on' if spec['transport'] == 'modern' else 'disable-modern=on')
    require(len(devices) == 3 and devices[0] == 'isa-debug-exit,iobase=0xf4,iosize=0x04' and
            devices[1] == virtio + ',netdev=net0,mac=02:00:00:00:00:01' and
            devices[2] == 'e1000,netdev=net1,mac=02:00:00:00:00:02', 'actual requested network devices')
    drives = [command[n + 1] for n, value in enumerate(command) if value == '-drive']
    if spec['firmware'] == 'uefi':
        original_directory = Path(command[command.index('-cdrom') + 1]).parent
        require(drives == ['if=pflash,format=raw,readonly=on,file=' + str(original_directory / 'OVMF_CODE.fd'),
                           'if=pflash,format=raw,file=' + str(original_directory / 'OVMF_VARS.fd')] and
                digest(directory / 'OVMF_CODE.fd') == firmware['code'] and
                digest(directory / 'OVMF_VARS.original.fd') == firmware['variables'],
                'actual retained UEFI code and isolated original variable store')
    else:
        require(not drives, 'original BIOS boot without substituted firmware drives')


def verify(directory):
    directory = Path(directory).resolve()
    index = decode((directory / 'matrix.json').read_text())
    require(type(index['schema']) is int and index['schema'] == 1 and index['complete'] is True and index['profiles'] == specifications() and
            type(index['workers']) is int and index['workers'] == 2, 'complete fixed thirty-three-profile source-route matrix')
    inputs = snapshot(directory, index['source'])
    for name in BOUND:
        require(inputs['scripts/ipv4_source_route/' + name] == digest(Path(__file__).with_name(name)),
                'same original public producers readers and independent native fixtures')
    require(digest(directory / 'kernel.elf') == index['kernel_sha256'], 'actual common current kernel')
    require(set(index['programs']) == {'native', 'static', 'dynamic'}, 'all common client linkages')
    proofs = {}
    native_configurations = set()
    for spec in specifications():
        case = directory / spec['path']
        receipt = decode((case / 'completed.json').read_text())
        require(all(receipt[name] == spec[name] for name in ('phase', 'mode', 'profile', 'firmware', 'transport')),
                'exact workload linkage firmware and transport declaration')
        require(decode((case / 'source/source-inputs.json').read_text()) == inputs and
                digest(case / 'program') == index['programs'][spec['profile']], 'same full source and byte-identical client per linkage')
        worker = decode((case / 'worker-process.json').read_text())
        require(worker['status'] == 'completed' and type(worker['returncode']) is int and worker['returncode'] == 0 and
                worker['log_sha256'] == digest(case / 'worker.log'), 'actual terminal campaign worker')
        if spec['mode'] == 'guest':
            require(digest(case / 'kernel.elf') == index['kernel_sha256'], 'same actual guest kernel in every profile')
            boot(case, spec, index['firmware'])
        else:
            native_wire(case)
            policy = decode((case / 'native-timer-policy.json').read_text())
            native_configurations.add((policy['kernel'], policy['config_sha256'], policy['hz']))
        boot_traffic(case, spec['mode'] == 'native')
        proofs[spec['path']] = observe(case, spec['phase'])
    require(len(native_configurations) == 1, 'same actual native kernel configuration in all nine native campaigns')
    for phase in PHASES:
        native = [proofs[f'{phase}-native-{profile}'] for profile in ('native', 'static', 'dynamic')]
        if phase in ('applications', 'queues'):
            key = 'semantics' if phase == 'applications' else 'outcomes'
            require(all(value[key] == native[0][key] for value in native), 'same measured behavior in all three native linkages')
            require(all(value[key] == native[0][key] for name, value in proofs.items()
                        if name.startswith(phase + '-guest-')), 'every guest matches the complete native behavior')
    model_proof = model.verify(directory / 'model')
    require(decode((directory / 'model/source-inputs.json').read_text()) == inputs,
            'ownership model uses the same complete current source')
    return dict(passed=True, profiles=33, cases_per_profile=dict(packets=47, applications=16, queues=16),
                source=index['source'], kernel_sha256=index['kernel_sha256'], programs=index['programs'],
                workers=2, observations_rescaled=False, all_native_capture_drops=0,
                bios_uefi_static_dynamic_modern_legacy=True, both_adapters=True, model=model_proof,
                source_route_matrix_complete=True, full_source_route_acceptance=False)


def build(directory):
    command = ['make', '-s', '-j4', 'build/axiom64.elf', 'build/init', 'busybox',
               'build/ipv4-source-route-host', 'build/ipv4-source-wire-static', 'build/ipv4-source-wire-dynamic']
    write(directory / 'build-command.json', command)
    with (directory / 'build.log').open('xb') as stream:
        subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, check=True)
    program = ROOT / 'build/ipv4-source-wire-native'
    command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               'userspace/tests/net/ipv4/source_route_wire.c', '-o', str(program)]
    before = sources(command, ROOT)
    subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, check=True)
    require(before == sources(command, ROOT), 'unchanged native compiler inputs')
    write(program.with_suffix('.inputs.json'), dict(command=command, sources=before,
          product=dict(bytes=program.stat().st_size, sha256=digest(program)),
          compiler_version=subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0]))
    programs = {}
    for profile in ('native', 'static', 'dynamic'):
        program = ROOT / 'build' / ('ipv4-source-wire-' + profile)
        audit_compile(program, ROOT)
        programs[profile] = digest(program)
    shutil.copy2(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    # The image helper owns mutable build aliases. Finish these serially before workers start.
    for phase in PHASES:
        for profile in ('static', 'dynamic'):
            target = directory / 'images' / (phase + '-' + profile)
            target.mkdir(parents=True)
            program = ROOT / 'build' / ('ipv4-source-wire-' + profile)
            def builder(provider, linkage, output):
                require(provider == 'build' and linkage == profile, 'exact guest compiler and linkage')
                return program, audit_compile(program, ROOT)
            fixture(target, 'build', profile, program_builder=builder, filename='ipv4-source-wire',
                    command='/bin/ipv4-source-wire ' + str(len(definition(phase))))
    return programs


def execute(directory, spec, parent, active, lock, stopping):
    case = directory / spec['path']
    # The worker creates its own directory; its launcher records stay beside it until it starts.
    log = directory / (spec['path'] + '.worker.log')
    command = [sys.executable, '-B', '-m', 'ipv4_source_route.worker', spec['mode'], spec['profile'],
               spec['phase'], str(case), '--source', str(directory / 'source'),
               '--firmware', spec['firmware'], '--transport', spec['transport']]
    if spec['mode'] == 'native':
        command = ['unshare', '--net', *command]
    else:
        command += ['--image', str(directory / 'images' / (spec['phase'] + '-' + spec['profile']))]
    environment = dict(os.environ, PYTHONPATH=str(ROOT / 'scripts'), IPV4_SOURCE_PARENT_NETNS=str(parent))
    began = time.monotonic_ns()
    timed_out = False
    with log.open('xb') as stream:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.STDOUT, env=environment, start_new_session=True)
        with lock:
            active[spec['path']] = process
            cancelled = stopping.is_set()
        if cancelled:
            stop(process)
        record = dict(pid=process.pid, command=command, status='running')
        write(directory / (spec['path'] + '.worker-process.json'), record)
        try:
            seconds = sum(row.get('observation_seconds', 5 if row['kind'] == 'held' else 1)
                          for row in definition(spec['phase']))
            process.wait(timeout=seconds + 180)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        finally:
            stop(process)
            with lock:
                active.pop(spec['path'], None)
    record.update(status='completed', returncode=process.returncode, timed_out=timed_out,
                  elapsed_ns=time.monotonic_ns() - began, log_sha256=digest(log))
    write(directory / (spec['path'] + '.worker-process.json'), record)
    if case.is_dir():
        shutil.copy2(log, case / 'worker.log')
        write(case / 'worker-process.json', record)
    require(not timed_out and process.returncode == 0, 'actual complete campaign failed: ' + spec['path'])
    return spec['path']


def produce(directory):
    directory = Path(directory).resolve()
    require(os.geteuid() == 0 and directory.is_relative_to((ROOT / 'build').resolve()),
            'root runner with designated ignored outputs and private native namespaces')
    directory.mkdir(parents=True, exist_ok=False)
    (directory / 'source').mkdir()
    source = freeze(directory / 'source')
    write(directory / 'source/binding.json', source)
    programs = build(directory)
    model.produce(directory / 'model')
    parent = Path('/proc/self/ns/net').stat().st_ino
    completed, failures = [], []
    active, lock, stopping = {}, threading.Lock(), threading.Event()
    pool = ThreadPoolExecutor(max_workers=2)
    try:
        futures = {pool.submit(execute, directory, spec, parent, active, lock, stopping): spec for spec in specifications()}
        for future in as_completed(futures):
            spec = futures[future]
            try:
                completed.append(future.result())
            except Exception as error:
                failures.append(dict(profile=spec['path'], error=str(error)))
            write(directory / 'progress.json', dict(completed=completed, failures=failures))
            print(json.dumps(dict(completed=len(completed), failed=len(failures), profile=spec['path'])), flush=True)
    except BaseException:
        stopping.set()
        pool.shutdown(wait=False, cancel_futures=True)
        with lock:
            processes = list(active.values())
        for process in processes:
            stop(process)
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    require(not failures, 'source-route campaigns failed; original evidence retained: ' + str(failures))
    inputs = decode((directory / 'source/source-inputs.json').read_text())
    names, _ = source_names()
    require(set(names) == set(inputs) and all(digest(ROOT / name) == value for name, value in inputs.items()),
            'unchanged complete public source throughout the matrix')
    write(directory / 'matrix.json', dict(schema=1, complete=True, profiles=specifications(), workers=2,
          source=source, programs=programs, kernel_sha256=digest(directory / 'kernel.elf'), firmware=dict(
          code=digest(Path('/usr/share/OVMF/OVMF_CODE_4M.fd')), variables=digest(Path('/usr/share/OVMF/OVMF_VARS_4M.fd')))))
    proof = verify(directory)
    write(directory / 'verified.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--produce', action='store_true')
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt('source-route matrix interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    print(json.dumps(produce(args.directory) if args.produce else verify(args.directory)), flush=True)


if __name__ == '__main__':
    main()

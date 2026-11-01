# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare IPv4 routing controls in isolated native and BIOS/UEFI guest processes."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile, sources
from fetch import ROOT
from ipv4_source_route.controls import CLIENT, client_binding, observations, require
from ipv4_source_route.evidence import verify
from ipv4_source_route.runtime import capture
from tcp6.inputs import digest, freeze, write


def execute(command, directory, name, *, native=None):
    write(directory / (name + '-command.json'), command)
    read_fd = write_fd = None
    descriptors = ()
    environment = dict(os.environ)
    if native:
        read_fd, write_fd = os.pipe()
        environment.update(IPV4_SOURCE_PARENT_NETNS=str(native['parent']),
                           IPV4_SOURCE_RUNTIME_FD=str(read_fd))
        descriptors = (read_fd,)
    began = time.monotonic_ns()
    process = None
    try:
        with (directory / (name + '.log')).open('xb') as stream:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream,
                                       stderr=subprocess.STDOUT, env=environment, pass_fds=descriptors)
            write(directory / (name + '-process.json'), dict(pid=process.pid, status='running'))
            if native:
                os.close(read_fd)
                read_fd = None
                capture(process, native['program'], native['executable'], directory,
                        native['profile'], native['parent'])
                os.write(write_fd, b'\xa5')
                os.close(write_fd)
                write_fd = None
            process.wait(timeout=30 if native else 90)
    finally:
        for descriptor in (read_fd, write_fd):
            if descriptor is not None:
                os.close(descriptor)
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            write(directory / (name + '-process.json'), dict(
                pid=process.pid, status='completed', returncode=process.returncode,
                elapsed_ns=time.monotonic_ns() - began,
                log_sha256=digest(directory / (name + '.log'))))
    require(process.returncode == (0 if native else 1), 'actual control process exit status')
    return observations((directory / (name + '.log')).read_text(), bool(native))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv4-source-controls')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'isolated native namespace and credential comparisons require root')
    directory = args.directory if args.directory.is_absolute() else ROOT / args.directory
    require(directory.resolve().is_relative_to((ROOT / 'build').resolve()), 'designated ignored output directory')
    directory.mkdir(parents=True, exist_ok=False)
    snapshot = freeze(directory)
    inputs = json.loads((directory / 'source-inputs.json').read_text())
    client_binding(inputs)
    command = ['make', '-s', '-j4', 'build/axiom64.elf', 'build/init', 'busybox',
               *('build/ipv4-source-controls-' + profile for profile in ('static', 'dynamic'))]
    write(directory / 'build-command.json', command)
    with (directory / 'build.log').open('xb') as stream:
        subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream,
                       stderr=subprocess.STDOUT, check=True)
    binary = ROOT / 'build/ipv4-source-controls-native'
    command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', CLIENT, '-o', str(binary)]
    before = sources(command, ROOT)
    subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, check=True)
    require(before == sources(command, ROOT), 'stable native compilation inputs')
    write(binary.with_suffix('.inputs.json'), dict(command=command, sources=before,
          product=dict(bytes=binary.stat().st_size, sha256=digest(binary)),
          compiler_version=subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0]))
    parent = Path('/proc/self/ns/net').stat().st_ino
    nodes = ['ip_forward', *(f'conf/{scope}/{key}' for scope in ('all', 'default', 'lo')
                            for key in ('accept_source_route', 'forwarding'))]
    def policy():
        return {node: (Path('/proc/sys/net/ipv4') / node).read_text() for node in nodes}
    original = policy()
    rows = []
    for profile in ('native', 'static', 'dynamic'):
        case = directory / ('native-' + profile)
        case.mkdir()
        program = ROOT / 'build' / ('ipv4-source-controls-' + profile)
        audit_compile(program, ROOT)
        shutil.copy2(program, case / 'program')
        shutil.copy2(program.with_suffix('.inputs.json'), case / 'program.inputs.json')
        executable = loader('build') if profile == 'dynamic' else program
        selected = [str(executable), str(program)] if profile == 'dynamic' else [str(program)]
        count = execute(['unshare', '--net', *selected], case, 'client', native=dict(
            parent=parent, program=program, executable=executable, profile=profile))
        require(original == policy(), 'parent namespace controls unchanged')
        rows.append(dict(case=case.name, native=True, profile=profile, observations=count))
    for profile in ('static', 'dynamic'):
        case = directory / profile
        case.mkdir()
        program = ROOT / 'build' / ('ipv4-source-controls-' + profile)
        def builder(provider, linkage, output):
            require(provider == 'build' and linkage == profile, 'fixed guest compiler and linkage')
            return program, audit_compile(program, ROOT)
        image = fixture(case, 'build', profile, program_builder=builder,
                        filename='ipv4-source-controls', command='/bin/ipv4-source-controls')
        shutil.copy2(program, case / 'program')
        shutil.copy2(program.with_suffix('.inputs.json'), case / 'program.inputs.json')
        for firmware in ('bios', 'uefi'):
            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                       '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                       '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            if firmware == 'uefi':
                variables = case / 'OVMF_VARS.fd'
                shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                            '-drive', 'if=pflash,format=raw,file=' + str(variables)]
            count = execute(command, case, firmware)
            rows.append(dict(case=profile, native=False, profile=profile, firmware=firmware, observations=count))
    require(inputs == {name: digest(ROOT / name) for name in inputs}, 'unchanged complete public source')
    write(directory / 'receipt.json', dict(source=snapshot, profiles=rows,
          parent_namespace_controls_unchanged=True, full_source_routing_acceptance=False))
    proof = verify(directory)
    write(directory / 'verified.json', proof)
    print(json.dumps(proof), flush=True)


if __name__ == '__main__':
    main()

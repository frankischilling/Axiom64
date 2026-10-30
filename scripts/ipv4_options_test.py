# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare IPv4 option syscalls and local packets in native and guest processes."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile
from fetch import ROOT
from ipv4_options.fixtures import LEGACY_SOCKET, SOCKET, RECEIVE, socket_table
from ipv4_options.native_policy import capture_policy
from ipv4_options_evidence import verify as verify_evidence
from ipv4_options_evidence_test import verify_controls
from tcp6.inputs import digest, freeze


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def native_runtime(process, program, executable, directory, profile):
    deadline = time.monotonic() + 10
    while process.poll() is None and time.monotonic() < deadline:
        try:
            maps = Path(f'/proc/{process.pid}/maps').read_text()
            actual = Path(f'/proc/{process.pid}/exe').resolve()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if actual != executable or str(program) not in maps:
            time.sleep(.002)
            continue
        if profile == 'native' and 'libc.so' not in maps:
            time.sleep(.002)
            continue
        (directory / 'runtime-maps.txt').write_text(maps)
        providers = {}
        for line in maps.splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith('/'):
                path = Path(fields[5])
                if path not in (program, executable) and ('.so' in path.name or 'ld-linux' in path.name):
                    providers[path] = int(fields[4])
        if providers:
            (directory / 'runtime').mkdir()
        retained = {}
        for number, (path, inode) in enumerate(providers.items()):
            require(path.stat().st_ino == inode, 'actual mapped native provider inode')
            name = 'runtime/' + str(number) + '-' + path.name
            shutil.copy2(path, directory / name)
            require(path.stat().st_ino == inode and digest(path) == digest(directory / name),
                    'unchanged mapped native provider bytes')
            retained[name] = dict(source=str(path), inode=inode, sha256=digest(directory / name))
        return dict(executable=str(actual), providers=retained,
                    maps_sha256=digest(directory / 'runtime-maps.txt'))
    raise ValueError('native option client did not reach its mapped-runtime barrier')


def run(command, directory, *, native=False, profile=None, program=None, suites=('socket',)):
    save(directory / 'command.json', command)
    began = time.monotonic_ns()
    environment = dict(os.environ)
    descriptors = ()
    read_fd = write_fd = None
    if native:
        read_fd, write_fd = os.pipe()
        environment['IPV4_OPTIONS_RUNTIME_FD'] = str(read_fd)
        descriptors = (read_fd,)
    with (directory / 'client.log').open('xb') as stream:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream,
                                   stderr=subprocess.STDOUT, env=environment, pass_fds=descriptors)
        save(directory / 'process.json', dict(pid=process.pid, status='running'))
        runtime = None
        try:
            if native:
                os.close(read_fd)
                read_fd = None
                executable = loader('build') if profile == 'dynamic' else program
                runtime = native_runtime(process, program, executable, directory, profile)
                os.write(write_fd, b'\1')
                os.close(write_fd)
                write_fd = None
            process.wait(timeout=120)
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            for descriptor in (read_fd, write_fd):
                if descriptor is not None:
                    os.close(descriptor)
    result = dict(pid=process.pid, status='completed', returncode=process.returncode,
                  elapsed_ns=time.monotonic_ns() - began, log_sha256=digest(directory / 'client.log'),
                  runtime=runtime)
    save(directory / 'process.json', result)
    text = (directory / 'client.log').read_text()
    require(process.returncode == (0 if native else 1), 'actual option client exit status')
    if 'socket' in suites:
        scopes = [f'IPV4_OPTIONS_SCOPE_PASS protocol={protocol} privileged={privileged} observations=7110'
                  for protocol in ('udp', 'tcp', 'raw') for privileged in (1, 0)]
        require(all(text.count(value) == 1 for value in scopes) and
                text.count('IPV4_OPTIONS_SCOPE_PASS ') == 6 and
                all(text.count(f'IPV4_OPTIONS_WIRE_PASS cases=8 uid={uid} ') == 1 for uid in (0, 65534)) and
                text.count('IPV4_OPTIONS_PASS protocols=3 observations=42660 scopes=6') == 1 and
                'IPV4_OPTIONS_FAIL' not in text, 'complete real option syscalls and local packets')
    if 'tcp' in suites:
        scopes = [f'IPV4_TCP_OPTIONS_SCOPE_PASS uid={uid} reset_cases=6 listener_cases=6 time_wait_cases=6 '
                  'time_wait_retained=3 time_wait_compacted=3 raw_protocols=261'
                  for uid in (0, 65534)]
        require(all(text.count(value) == 1 for value in scopes) and
                text.count('IPV4_TCP_OPTIONS_SCOPE_PASS ') == 2 and
                text.count('IPV4_TCP_OPTIONS_PASS scopes=2 cases=36') == 1 and
                'IPV4_TCP_OPTIONS_FAIL' not in text, 'complete actual TCP option responses and owned queries')
    if not native:
        require(text.count('AXIOM64_TESTS_PASS') == 1 and text.count('AXIOM64_EXIT status=0') == 1,
                'successful guest test process')
    return result, text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv4-options')
    parser.add_argument('--workers', type=int, default=2)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'native raw socket and credential fixtures require root')
    directory = args.directory if args.directory.is_absolute() else ROOT / args.directory
    require(directory.resolve().is_relative_to((ROOT / 'build').resolve()), 'designated ignored output directory')
    require(1 <= args.workers <= 32, 'bounded build workers')
    directory.mkdir(parents=True, exist_ok=False)
    frozen = directory / 'source'
    frozen.mkdir()
    source = freeze(frozen)
    inputs = json.loads((frozen / 'source-inputs.json').read_text())
    table = directory / 'options-oracle.tsv'
    table.write_bytes(socket_table())
    native_policy, native_fixture = capture_policy()
    save(directory / 'native-policy.json', native_policy)
    native_table = directory / 'native-options-oracle.tsv'
    native_table.write_bytes(socket_table(native_fixture))
    kernel = ROOT / 'build/axiom64.elf'
    if kernel.exists() and kernel.stat().st_nlink > 1:
        detached = kernel.with_name('axiom64-options-detached.elf')
        require(not detached.exists() and kernel.is_file() and not kernel.is_symlink(), 'unused kernel detachment path')
        shutil.copy2(kernel, detached)
        require(digest(detached) == digest(kernel) and detached.stat().st_nlink == 1, 'verified independent kernel')
        os.replace(detached, kernel)
    targets = ['build/axiom64.elf', 'build/init', 'busybox', 'test-ipv4-options-model',
               *('build/' + name + '-' + profile for name in ('ipv4-options', 'ipv4-tcp-options')
                 for profile in ('native', 'static', 'dynamic'))]
    command = ['make', '-j' + str(args.workers), *targets]
    save(directory / 'build-command.json', command)
    with (directory / 'build.log').open('xb') as stream:
        subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stream,
                       stderr=subprocess.STDOUT, check=True, timeout=600)
    kernel_sha256 = digest(kernel)
    results = []
    for profile in ('native', 'static', 'dynamic'):
        for suite, name in (('socket', 'ipv4-options'), ('tcp', 'ipv4-tcp-options')):
            case = directory / ('linux-' + suite + '-' + profile)
            case.mkdir()
            program = ROOT / ('build/' + name + '-' + profile)
            command = ([str(loader('build'))] if profile == 'dynamic' else []) + [str(program)]
            if suite == 'socket':
                command.append(str(native_table))
            result, _ = run(command, case, native=True, profile=profile, program=program, suites=(suite,))
            shutil.copy2(program, case / 'program.elf')
            if profile != 'native':
                audit_compile(program, ROOT)
                shutil.copy2(program.with_suffix('.inputs.json'), case / 'program.inputs.json')
            if profile == 'dynamic':
                shutil.copy2(loader('build'), case / 'loader.elf')
            result.update(native=True, profile=profile, suites=[suite], kernel=os.uname().release,
                          program_sha256=digest(program), native_fixture=native_fixture.name)
            save(case / 'results.json', result)
            results.append(result)
    for profile in ('static', 'dynamic'):
        program = ROOT / ('build/ipv4-options-' + profile)
        provenance = audit_compile(program, ROOT)
        tcp_program = ROOT / ('build/ipv4-tcp-options-' + profile)
        audit_compile(tcp_program, ROOT)
        for firmware in ('bios', 'uefi'):
            case = directory / (profile + '-' + firmware)
            case.mkdir()
            image = fixture(case, 'build', profile, program_builder=lambda *unused: (program, provenance),
                            filename='ipv4-options', command='/bin/ipv4-options /etc/options-oracle.tsv && /bin/ipv4-tcp-options',
                            extra_products={'etc/options-oracle.tsv': table, 'bin/ipv4-tcp-options': tcp_program})
            shutil.copy2(program, case / 'program.elf')
            shutil.copy2(program.with_suffix('.inputs.json'), case / 'program.inputs.json')
            shutil.copy2(tcp_program, case / 'tcp-program.elf')
            shutil.copy2(tcp_program.with_suffix('.inputs.json'), case / 'tcp-program.inputs.json')
            require(digest(case / 'kernel.elf') == kernel_sha256, 'actual unchanged boot kernel')
            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M', '-nic', 'none',
                       '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                       '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            if firmware == 'uefi':
                variables = case / 'OVMF_VARS.fd'
                shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                            '-drive', 'if=pflash,format=raw,file=' + str(variables)]
            result, text = run(command, case, suites=('socket', 'tcp'))
            require(text.count('Firmware: ' + firmware.upper()) == 1, 'actual requested guest firmware')
            result.update(native=False, profile=profile, firmware=firmware, suites=['socket', 'tcp'],
                          kernel_sha256=kernel_sha256, program_sha256=digest(program),
                          tcp_program_sha256=digest(tcp_program),
                          products={name: digest(case / name) for name in ('kernel.elf', 'root.cpio', 'image.iso')})
            save(case / 'results.json', result)
            results.append(result)
    require(all(digest(ROOT / name) == value for name, value in inputs.items()), 'stable corresponding source')
    require(digest(kernel) == kernel_sha256, 'stable actual guest kernel')
    record = dict(passed=True, source=source, kernel_sha256=kernel_sha256, executions=results,
                  socket_fixture_sha256=digest(SOCKET), receive_fixture_sha256=digest(RECEIVE),
                  legacy_socket_fixture_sha256=digest(LEGACY_SOCKET),
                  native_fixture=native_fixture.name, native_table_sha256=digest(native_table),
                  native_policy_sha256=digest(directory / 'native-policy.json'),
                  table_sha256=digest(table), native_profiles=3, guest_profiles=4,
                  socket_observations_each=42660, actual_loopback_wire_cases_each=16,
                  tcp_response_cases_each=36, native_executions=6, guest_boots=4,
                  ethernet_and_full_feature_acceptance=False)
    save(directory / 'results.json', record)
    save(directory / 'independent-evidence.json', verify_evidence(directory))
    verify_controls(directory, directory / 'damaged-evidence')
    print(json.dumps({key: value for key, value in record.items() if key != 'executions'}))


if __name__ == '__main__':
    main()

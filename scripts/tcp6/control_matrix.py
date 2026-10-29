#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run identical IPv6 TCP control clients on Linux and BIOS/UEFI guests."""
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile
from compile_uapi_client import sources as compile_sources
from fetch import LOCK, ROOT
from tcp6.inputs import digest, freeze, write
from tcp_fixture_inputs import audit_fixture


from tcp6.control_contract import ABI, STATE


def run_glibc(directory, suite):
    if suite not in (ABI, STATE):
        raise ValueError('unknown Internet stream control contract')
    directory = Path(directory)
    source = json.loads((directory / 'results.json').read_text())['source']
    case = directory / 'glibc'
    case.mkdir()
    program = case / 'program'
    command = ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               suite.source, '-o', str(program)]
    inputs = compile_sources(command, ROOT)
    with (case / 'compile.log').open('xb') as log:
        subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    if compile_sources(command, ROOT) != inputs:
        raise ValueError('glibc control sources changed while compiling')
    compiled = dict(command=command, sources=inputs, product=dict(
        bytes=program.stat().st_size, sha256=digest(program)),
        compiler_version=subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0])
    write(program.with_suffix('.inputs.json'), compiled)
    audit_compile(program, ROOT)
    dependencies = subprocess.check_output(['ldd', str(program)], text=True)
    (case / 'ldd.log').write_text(dependencies)
    libraries = {}
    for line in dependencies.splitlines():
        fields = line.split()
        actual = fields[2] if len(fields) >= 3 and fields[1] == '=>' else fields[0] if fields else ''
        if not actual.startswith('/'):
            continue
        path = Path(actual).resolve(strict=True)
        target = case / 'runtime' / path.name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(path, target)
        libraries[path.name] = dict(file='runtime/' + path.name, bytes=target.stat().st_size,
                                   sha256=digest(target), actual_path=str(path))
    if set(libraries) != {'libc.so.6', 'ld-linux-x86-64.so.2'}:
        raise ValueError('glibc control runtime must retain every actual shared library')
    write(case / 'before.json', dict(source=source, command=[str(program)], deadline_seconds=60,
        kernel=platform.release(), program_sha256=digest(program), libraries=libraries,
        compiler_inputs_sha256=digest(program.with_suffix('.inputs.json'))))
    with (case / 'client.log').open('xb') as log:
        result = subprocess.run([str(program)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=60)
    passed = (result.returncode == 0 and (case / 'client.log').read_text().splitlines().count(suite.marker) == 1)
    write(case / 'result.json', dict(passed=passed, returncode=result.returncode,
        program_sha256=digest(program), log_sha256=digest(case / 'client.log'),
        before_sha256=digest(case / 'before.json')))
    if not passed:
        raise RuntimeError('actual glibc Internet stream control comparison failed')
    if any(digest(Path(item['actual_path'])) != item['sha256'] for item in libraries.values()):
        raise ValueError('glibc runtime changed during the control comparison')


def run_matrix(directory, suite, verifier):
    if suite not in (ABI, STATE):
        raise ValueError('unknown Internet stream control contract')
    directory = Path(directory).resolve()
    if not directory.is_relative_to((ROOT / 'build').resolve()):
        raise ValueError('output must be a fresh owned directory below build/')
    directory.mkdir(parents=True, exist_ok=False)
    source = freeze(directory)
    kernel = digest(ROOT / 'build/axiom64.elf')
    rows = []
    for profile in ('static', 'dynamic'):
        case = directory / profile
        case.mkdir()
        program = case / 'program'
        command = [sys.executable, '-B', 'scripts/compile_uapi_client.py', '--output', str(program), '--',
            '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
            *(['-static'] if profile == 'static' else []), suite.source]
        subprocess.run(command, cwd=ROOT, check=True)
        compiled = audit_compile(program, ROOT)
        native_command = [str(program)]
        if profile == 'dynamic':
            shutil.copy2(loader('build'), case / 'loader')
            native_command.insert(0, str(case / 'loader'))
        write(case / 'native-before.json', dict(command=native_command, source=source,
            deadline_seconds=60, program_sha256=digest(program), kernel=platform.release(),
            loader_sha256=digest(case / 'loader') if profile == 'dynamic' else None))
        with (case / 'native.log').open('xb') as log:
            completed = subprocess.run(native_command, cwd=ROOT, stdout=log,
                stderr=subprocess.STDOUT, timeout=60)
        text = (case / 'native.log').read_text()
        passed = completed.returncode == 0 and text.splitlines().count(suite.marker) == 1
        rows.append(dict(profile=profile, environment='native', passed=passed,
            returncode=completed.returncode, program_sha256=digest(program),
            log_sha256=digest(case / 'native.log')))
        write(directory / 'results.json', dict(source=source, results=rows, complete=False))
        if not passed:
            raise RuntimeError('IPv6 TCP native control comparison failed: ' + profile)
        image = fixture(case, 'build', profile, filename=suite.program, command='/bin/' + suite.program,
            program_builder=lambda *ignored: (program, compiled))
        script = ('#!/bin/sh\nset -e\n/bin/' + suite.program + '\necho AXIOM64_TESTS_PASS\n').encode()
        products = {'sbin/init': digest(ROOT / 'build/init'), 'bin/' + suite.program: digest(program),
            'bin/busybox': digest(ROOT / ('build/busybox-' + LOCK['busybox']['version']) / 'busybox'),
            'lib/ld-musl-x86_64.so.1': digest(loader('build'))}
        audit = audit_fixture(image, kernel, products, script)
        write(case / 'image-audit.json', dict(audit=audit, kernel_sha256=kernel,
            products=products, script=script.decode()))
        for firmware in ('bios', 'uefi'):
            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none',
                '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            firmware_inputs = {}
            if firmware == 'uefi':
                variables = case / 'OVMF_VARS.fd'
                shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                code = Path('/usr/share/OVMF/OVMF_CODE_4M.fd')
                firmware_inputs = dict(code_sha256=digest(code), variables_before_sha256=digest(variables))
                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=' + str(code),
                            '-drive', 'if=pflash,format=raw,file=' + str(variables)]
            write(case / (firmware + '-before.json'), dict(command=command, source=source,
                deadline_seconds=90, kernel_sha256=kernel, program_sha256=digest(program),
                image_sha256=digest(image), firmware_inputs=firmware_inputs))
            began = time.monotonic_ns()
            with (case / (firmware + '.log')).open('xb') as log:
                process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=subprocess.STDOUT)
                try:
                    returncode = process.wait(timeout=90)
                except BaseException:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    raise
            text = (case / (firmware + '.log')).read_text()
            passed = (returncode == 1 and text.splitlines().count(suite.marker) == 1 and
                text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                'Firmware: ' + firmware.upper() in text and 'AXIOM64_EXIT status=0' in text and
                not any(failure in text for failure in (suite.failure, 'PANIC:', 'FAULT pid=')))
            rows.append(dict(profile=profile, environment=firmware, passed=passed,
                returncode=returncode, elapsed_ns=time.monotonic_ns()-began,
                program_sha256=digest(program), kernel_sha256=digest(case / 'kernel.elf'),
                image_sha256=digest(image), log_sha256=digest(case / (firmware + '.log'))))
            write(directory / 'results.json', dict(source=source, results=rows, complete=False))
            if not passed:
                raise RuntimeError('IPv6 TCP guest control comparison failed: ' + profile + '/' + firmware)
            print(suite.label + '_GUEST_PASS ' + profile + '/' + firmware, flush=True)
    if digest(ROOT / 'build/axiom64.elf') != kernel:
        raise RuntimeError('IPv6 TCP kernel changed during control comparison')
    recorded = json.loads((directory / 'source-inputs.json').read_text())
    if any(digest(ROOT / name) != fingerprint for name, fingerprint in recorded.items()):
        raise RuntimeError('IPv6 TCP sources changed during control comparison')
    write(directory / 'results.json', dict(source=source, results=rows, complete=True, passed=True))
    result = verifier(directory)
    if any(digest(ROOT / name) != fingerprint for name, fingerprint in recorded.items()):
        raise RuntimeError('Internet stream control sources changed during final verification')
    write(directory / 'independent-audit.json', result)
    return result

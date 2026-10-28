# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the same IPv4 receive-control client under Linux and four guest profiles."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from fetch import ROOT
from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile
from tcp6.inputs import digest, freeze
from ipv4_receive_controls_contract import DONE, damaged_controls, require, verify


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def run(command, directory, expected=0, timeout=120):
    save(directory / 'command.json', command)
    began = time.monotonic_ns()
    with (directory / 'client.log').open('xb') as output:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT)
        save(directory / 'process.json', dict(pid=process.pid, status='running', command=command))
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        except BaseException:
            process.kill()
            process.wait()
            raise
    result = dict(pid=process.pid, status='completed', returncode=process.returncode,
                  timed_out=timed_out, elapsed_ns=time.monotonic_ns() - began,
                  log_sha256=digest(directory / 'client.log'))
    save(directory / 'process.json', result)
    require(not timed_out and process.returncode == expected, 'actual client process failed: ' + str(directory))
    text = (directory / 'client.log').read_text()
    require(text.count(DONE) == 1 and 'IPV4_RECEIVE_CONTROLS_FAIL' not in text,
            'complete common client execution: ' + str(directory))
    return result, text


def detach_kernel():
    kernel = ROOT / 'build/axiom64.elf'
    if not kernel.exists():
        return
    require(kernel.is_file() and not kernel.is_symlink(), 'regular writable build kernel')
    if kernel.stat().st_nlink > 1:
        temporary = kernel.with_name('axiom64-receive-detached.elf')
        require(not temporary.exists(), 'unused kernel detachment destination')
        original = digest(kernel)
        shutil.copy2(kernel, temporary)
        require(digest(temporary) == original and temporary.stat().st_nlink == 1,
                'independent verified kernel copy before linking')
        os.replace(temporary, kernel)


def main():
    if '--native-child' in sys.argv:
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        command = sys.argv[sys.argv.index('--native-child') + 1:]
        os.execv(command[0], command)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv4-receive-controls')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    directory = args.directory if args.directory.is_absolute() else ROOT / args.directory
    require(directory.resolve().is_relative_to((ROOT / 'build').resolve()), 'designated ignored output directory')
    require(1 <= args.workers <= 32, 'bounded build workers')
    directory.mkdir(parents=True, exist_ok=False)
    frozen = directory / 'source'
    frozen.mkdir()
    source = freeze(frozen)
    inputs = json.loads((frozen / 'source-inputs.json').read_text())
    detach_kernel()
    targets = ['build/axiom64.elf', *('build/ipv4-receive-controls-' + profile
               for profile in ('native', 'static', 'dynamic'))]
    command = ['make', '-j' + str(args.workers), *targets]
    save(directory / 'build-command.json', command)
    with (directory / 'build.log').open('xb') as output:
        subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True, timeout=600)
    kernel_sha256 = digest(ROOT / 'build/axiom64.elf')
    native_texts, guest_texts, results = [], [], []
    for profile in ('native', 'static', 'dynamic'):
        case = directory / ('linux-' + profile)
        case.mkdir()
        program = ROOT / ('build/ipv4-receive-controls-' + profile)
        execution = ([str(loader('build'))] if profile == 'dynamic' else []) + [str(program)]
        command = ['unshare', '--net', sys.executable, '-B', __file__, '--native-child', *execution]
        result, text = run(command, case, timeout=30)
        native_texts.append(text)
        result.update(profile=profile, native=True, program_sha256=digest(program), source=source)
        if profile != 'native':
            audit_compile(program, ROOT)
            shutil.copy2(program.with_suffix('.inputs.json'), case / 'program.inputs.json')
        shutil.copy2(program, case / 'program.elf')
        if profile == 'dynamic':
            shutil.copy2(loader('build'), case / 'loader.elf')
        save(case / 'results.json', result)
        results.append(result)
    for profile in ('static', 'dynamic'):
        program = ROOT / ('build/ipv4-receive-controls-' + profile)
        compiler = audit_compile(program, ROOT)
        for firmware in ('bios', 'uefi'):
            case = directory / (profile + '-' + firmware)
            case.mkdir()
            # The fixture embeds this exact audited ELF and the selected loader.
            image = fixture(case, 'build', profile,
                program_builder=lambda *unused: (program, compiler),
                filename='ipv4-receive-controls', command='/bin/ipv4-receive-controls')
            shutil.copy2(program, case / 'program.elf')
            shutil.copy2(program.with_suffix('.inputs.json'), case / 'program.inputs.json')
            require(digest(case / 'kernel.elf') == kernel_sha256, 'unchanged actual boot kernel')
            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
                '-nic', 'none', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
                '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            if firmware == 'uefi':
                variables = case / 'OVMF_VARS.fd'
                shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                            '-drive', 'if=pflash,format=raw,file=' + str(variables)]
            result, text = run(command, case, expected=1)
            require(text.count('Firmware: ' + firmware.upper()) == 1, 'actual requested guest firmware')
            guest_texts.append(text)
            result.update(profile=profile, firmware=firmware, native=False, source=source,
                          kernel_sha256=kernel_sha256, program_sha256=digest(program),
                          products={name: digest(case / name) for name in
                                    ('kernel.elf', 'program.elf', 'image.iso', 'root.cpio')})
            save(case / 'results.json', result)
            results.append(result)
    checked = verify(native_texts, guest_texts)
    checked['serialized_controls_rejected'] = damaged_controls(
        native_texts, guest_texts, directory / 'damaged-controls.zip')
    require(all(digest(ROOT / name) == value for name, value in inputs.items()),
            'corresponding source unchanged during complete cohort')
    require(digest(ROOT / 'build/axiom64.elf') == kernel_sha256, 'runtime kernel unchanged')
    checked.update(source=source, actual_kernel_sha256=kernel_sha256, executions=results,
                   full_feature_acceptance=False, physical_interface_coverage=False)
    save(directory / 'results.json', checked)
    print(json.dumps({key: value for key, value in checked.items() if key != 'executions'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

# SPDX-License-Identifier: GPL-3.0-or-later
"""Run all 384 IPv4 send-control cases in three Linux and four guest profiles."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from account_store_guest import fixture
from build_musl import loader
from compile_uapi_client import audit_compile
from fetch import ROOT
from ipv4_send_controls_contract import DONE, require, verify
from ipv4_send_controls_records import verify as records
from tcp6.inputs import digest, freeze, source_names


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def detach(path):
    if path.exists() and path.stat().st_nlink > 1:
        temporary = path.with_name(path.name + '.send-controls-detached')
        require(not temporary.exists() and path.is_file() and not path.is_symlink(), 'unused regular detachment destination')
        shutil.copy2(path, temporary)
        require(digest(temporary) == digest(path) and temporary.stat().st_nlink == 1, 'verified independent build output')
        os.replace(temporary, path)


def run(command, directory, profile, native, firmware=None):
    timeout = 30 if native else 120
    save(directory / 'command.json', command)
    began = time.monotonic_ns()
    maps, runtime = '', {}
    timed_out = False
    with (directory / 'client.log').open('xb') as output:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        save(directory / 'process.json', dict(pid=process.pid, status='running', command=command))
        try:
            while process.poll() is None:
                if native and not maps:
                    try:
                        current = Path(f'/proc/{process.pid}/maps').read_text()
                        executable = Path(f'/proc/{process.pid}/exe').resolve()
                        ready = executable in (directory / 'program.elf', directory / 'loader.elf') and str(directory / 'program.elf') in current
                        if profile == 'native':
                            ready = ready and 'libc.so' in current
                        if ready:
                            providers = {}
                            for line in current.splitlines():
                                fields = line.split(None, 5)
                                if len(fields) != 6 or not fields[5].startswith('/'):
                                    continue
                                path = Path(fields[5])
                                if path in (directory / 'program.elf', directory / 'loader.elf'):
                                    continue
                                if '.so' in path.name or 'ld-linux' in path.name:
                                    providers[path] = int(fields[4])
                            if providers:
                                (directory / 'runtime').mkdir()
                            for number, (path, inode) in enumerate(providers.items()):
                                require(path.stat().st_ino == inode, 'actual mapped provider inode')
                                name = 'runtime/' + str(number) + '-' + path.name
                                shutil.copy2(path, directory / name)
                                runtime[name] = dict(source=str(path), inode=inode, sha256=digest(directory / name))
                            maps = current
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                if time.monotonic_ns() - began >= timeout * 1000000000:
                    timed_out = True
                    process.kill()
                    break
                time.sleep(.002)
            process.wait()
        except BaseException:
            process.kill()
            process.wait()
            raise
    result = dict(pid=process.pid, status='completed', returncode=process.returncode, timed_out=timed_out,
                  elapsed_ns=time.monotonic_ns() - began, timeout_seconds=timeout)
    save(directory / 'process.json', result)
    result.update(profile=profile, native=native, firmware=firmware,
                  label='linux-' + profile if native else profile + '-' + firmware,
                  log_sha256=digest(directory / 'client.log'), command=command, passed=False)
    products = {'program.elf', 'program.inputs.json'} | ({'loader.elf'} if profile == 'dynamic' else set())
    if native:
        (directory / 'maps.txt').write_text(maps)
        result.update(maps_sha256=digest(directory / 'maps.txt'), runtime=runtime,
                      runtime_unchanged=all(digest(Path(row['source'])) == row['sha256'] for row in runtime.values()),
                      executed_program=str(directory / 'program.elf'), program_inode=(directory / 'program.elf').stat().st_ino)
        if profile == 'dynamic':
            result.update(executed_loader=str(directory / 'loader.elf'), loader_inode=(directory / 'loader.elf').stat().st_ino)
    else:
        products |= {'kernel.elf', 'image.iso', 'root.cpio'}
    result['products'] = {name: digest(directory / name) for name in products}
    save(directory / 'results.json', result)
    require(not timed_out and process.returncode == (0 if native else 1), 'actual common client process failed')
    text = (directory / 'client.log').read_text()
    records(text)
    require(not native or bool(maps), 'live original client maps were observed')
    result['passed'] = True
    save(directory / 'results.json', result)
    print(json.dumps(dict(label=result['label'], passed=True, elapsed_ns=result['elapsed_ns'])), flush=True)


def main():
    if '--native-child' in sys.argv:
        position = sys.argv.index('--native-child')
        directory = Path(sys.argv[position + 1])
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True, stdin=subprocess.DEVNULL)
        configuration = dict(namespace_inode=os.stat('/proc/self/ns/net').st_ino,
                             kernel=os.uname()._asdict() if hasattr(os.uname(), '_asdict') else
                             dict(zip(('sysname', 'nodename', 'release', 'version', 'machine'), os.uname())))
        for key, arguments in [('links', ['link', 'show']), ('addresses', ['address', 'show']), ('routes', ['route', 'show'])]:
            configuration[key] = json.loads(subprocess.check_output(['ip', '-json', *arguments], stdin=subprocess.DEVNULL))
        save(directory / 'native-configuration.json', configuration)
        command = sys.argv[position + 2:]
        os.execv(command[0], command)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv4-send-controls')
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    directory = args.directory.resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()) and 1 <= args.workers <= 32,
            'designated ignored output directory and bounded workers')
    directory.mkdir(parents=True, exist_ok=False)
    source = freeze(directory)
    original = json.loads((directory / 'source-inputs.json').read_text())
    targets = ['build/axiom64.elf', 'build/init', 'busybox',
               *['build/ipv4-send-controls-' + profile for profile in ('native', 'static', 'dynamic')]]
    for name in targets:
        detach(ROOT / name)
    command = ['make', '-j' + str(args.workers), *targets]
    save(directory / 'build-command.json', command)
    with (directory / 'build.log').open('xb') as output:
        subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                       check=True, timeout=600)
    kernel = digest(ROOT / 'build/axiom64.elf')
    receipt = dict(source=source, kernel_sha256=kernel, cases=[], passed=False)
    save(directory / 'acceptance.json', receipt)
    for native, profile, firmware in ([(True, profile, None) for profile in ('native', 'static', 'dynamic')] +
            [(False, profile, firmware) for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi')]):
        label = 'linux-' + profile if native else profile + '-' + firmware
        selected = directory / label
        selected.mkdir()
        program = ROOT / ('build/ipv4-send-controls-' + profile)
        compiled = audit_compile(program, ROOT)
        shutil.copy2(program, selected / 'program.elf')
        shutil.copy2(program.with_suffix('.inputs.json'), selected / 'program.inputs.json')
        if profile == 'dynamic':
            shutil.copy2(loader('build'), selected / 'loader.elf')
        if native:
            execution = ([str(selected / 'loader.elf')] if profile == 'dynamic' else []) + [str(selected / 'program.elf')]
            command = ['unshare', '--net', sys.executable, '-B', __file__, '--native-child', str(selected), *execution]
        else:
            image = fixture(selected, 'build', profile, program_builder=lambda *unused: (program, compiled),
                            filename='ipv4-send-controls', command='/bin/ipv4-send-controls')
            require(digest(selected / 'kernel.elf') == kernel, 'unchanged actual boot kernel')
            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M', '-nic', 'none',
                       '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
                       '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
            if firmware == 'uefi':
                shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', selected / 'OVMF_VARS.fd')
                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                            '-drive', 'if=pflash,format=raw,file=' + str(selected / 'OVMF_VARS.fd')]
        run(command, selected, profile, native, firmware)
        receipt['cases'].append(label)
        save(directory / 'acceptance.json', receipt)
    names, _ = source_names()
    receipt['source_unchanged'] = set(names) == set(original) and all(digest(ROOT / name) == value for name, value in original.items())
    require(receipt['source_unchanged'] and digest(ROOT / 'build/axiom64.elf') == kernel, 'unchanged complete cohort source and kernel')
    receipt['passed'] = True
    save(directory / 'acceptance.json', receipt)
    checked = verify(directory)
    save(directory / 'readback.json', checked)
    from ipv4_send_controls_damaged import damaged
    checked['serialized_controls_rejected'] = damaged(directory, directory / 'damaged-controls.zip')
    save(directory / 'results.json', checked)
    print(json.dumps(checked), flush=True)


if __name__ == '__main__':
    main()

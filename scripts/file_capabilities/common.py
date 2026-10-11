# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain the actual executable, boot image, disk and deadline for each run."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from fetch import ROOT, LOCK
from build_musl import loader
from build_libcap import ensure as libcap


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def prepare():
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    'build/file-capabilities-native', 'build/file-capabilities-static',
                    'build/file-capabilities-dynamic'], cwd=ROOT, check=True)
    libcap('build')


def image(output, label, linkage, script):
    files = {name: (0o40755, b'') for name in ('bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'tmp', 'run')}
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         ('bin/file-capabilities-tests', ROOT / 'build' / ('file-capabilities-' + linkage)),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}/busybox"),
                         ('lib/ld-musl-x86_64.so.1', loader())]:
        files[name] = (0o100755, source.read_bytes())
    tools = libcap('build')
    for name in ('getcap', 'setcap'):
        for profile in ('static', 'dynamic'):
            files[f'bin/{name}-{profile}'] = (0o100755, (tools / f'{name}-{profile}').read_bytes())
    files['etc/net-test.sh'] = (0o100755, ('#!/bin/sh\nset -e\nexport FILECAP_TOOLS=/bin\n' + script +
                                       '\necho AXIOM64_TESTS_PASS\n').encode())
    archive = ROOT / 'build/rootfs-network.cpio'
    previous = archive.read_bytes() if archive.exists() else None
    try:
        with archive.open('wb') as stream:
            for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
                encoded = name.encode() + b'\0'
                fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
                stream.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
                stream.write(bytes(-stream.tell() % 4))
                stream.write(data)
                stream.write(bytes(-stream.tell() % 4))
        shutil.copy2(archive, output / (label + '.cpio'))
        name = 'axiom64-filecap-' + label + '.iso'
        with (output / (label + '-image.log')).open('wb') as stream:
            subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network', '--output-name', name],
                           cwd=ROOT, check=True, stdout=stream, stderr=subprocess.STDOUT)
        destination = output / name
        shutil.copy2(ROOT / 'build' / name, destination)
        return destination
    finally:
        if previous is None:
            archive.unlink(missing_ok=True)
        else:
            archive.write_bytes(previous)


def boot(output, label, iso, disk=None, firmware='bios', transport='modern', rules=None, timeout=120, memory='512M'):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', memory, '-nic', 'none',
               '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for index, current in enumerate(disk if isinstance(disk, list) else [disk] if disk else []):
        rule = rules[index] if isinstance(rules, list) else rules
        backend = f'blkdebug:{rule}:{current}' if rule else str(current)
        mode = 'disable-legacy=on' if transport == 'modern' else 'disable-modern=on'
        command += ['-drive', f'if=none,format=raw,cache=writeback,file={backend},id=filecap{index}',
                    '-device', f'virtio-blk-pci,drive=filecap{index},{mode},rerror=report,werror=report']
    if firmware == 'uefi':
        variables = output / (label + '-VARS.fd')
        shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    log = output / (label + '.log')
    timed_out, started = False, time.monotonic_ns()
    wall_started = time.time_ns()
    with log.open('wb') as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    text = log.read_text(errors='replace')
    record = dict(label=label, firmware=firmware, transport=transport, timeout_seconds=timeout,
                  started_ns=wall_started, elapsed_ns=time.monotonic_ns() - started,
                  command=command, returncode=process.returncode, timed_out=timed_out,
                  image=iso.name, image_sha256=digest(iso), log=log.name, log_sha256=digest(log),
                  passed=not timed_out and process.returncode == 1 and
                  all(marker in text for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0',
                                                     'Firmware: ' + firmware.upper())) and
                  not any(marker in text for marker in ('FILECAP_TEST_FAIL ', 'PANIC:', 'FAULT pid=')))
    save(output / (label + '-boot.json'), record)
    print('FILECAP_BOOT label=' + label + ' passed=' + str(record['passed']), flush=True)
    if not record['passed']:
        print(text[-5000:], flush=True)
        raise RuntimeError('file capability boot failed: ' + label)
    return record


def debugfs(disk, command, output=None, write=False):
    result = subprocess.run(['/usr/sbin/debugfs', *(['-w'] if write else []), '-R', command, str(disk)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    if output:
        Path(output).write_bytes(result.stdout)
    return result.stdout.decode(errors='replace')


def fsck(disk, output, label):
    log = output / (label + '-fsck.log')
    result = subprocess.run(['/usr/sbin/e2fsck', '-fn', str(disk)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_bytes(result.stdout)
    if result.returncode:
        raise RuntimeError('independent ext2 check failed: ' + str(log))
    return dict(log=log.name, sha256=digest(log), returncode=result.returncode)


def volume(disk, block=1024, inode=128, original=False, capacity=32 * 1024 * 1024):
    with disk.open('wb') as stream:
        stream.truncate(capacity)
    command = ['/usr/sbin/mke2fs', '-q', '-F', '-t', 'ext2', '-b', str(block), '-I', str(inode)]
    if original:
        command += ['-r', '0', '-O', 'none']
    result = subprocess.run(command + [str(disk)], check=True, capture_output=True)
    disk.with_suffix('.mkfs.log').write_bytes(result.stdout + result.stderr)


def snapshot(output, native=False):
    """Copy inputs, including relinkable archives and complete upstream notices."""
    target = output / 'inputs'
    target.mkdir()
    sources = []
    for directory in ('kernel', 'userspace', 'scripts', 'config', 'vendor'):
        sources += [path for path in (ROOT / directory).rglob('*') if path.is_file() and
                    '__pycache__' not in path.parts and path.suffix != '.pyc']
    sources += [ROOT / name for name in ('Makefile', 'dependencies.json', 'sources.lock.json',
                                       'ports.lock.json', 'LICENSE', 'COPYING') if (ROOT / name).is_file()]
    products = [ROOT / 'build' / name for name in ('axiom64.elf', 'init', 'file-capabilities-static',
                                                  'file-capabilities-dynamic', 'file-capabilities-native')]
    products += [ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}/busybox"]
    for provider in ('build', 'runtime', 'native') if native else ('build', 'runtime'):
        directory = libcap(provider)
        products += [directory / 'manifest.json', directory / 'build.log']
        products += [directory / f'{name}-{linkage}' for name in ('getcap', 'setcap')
                     for linkage in ('static', 'dynamic')]
        source = directory / 'source' / ('libcap-' + LOCK['libcap']['version'])
        products += [source / 'License', source / 'libcap/libcap.a']
    from build_musl import ensure
    for provider in ('build', 'runtime'):
        directory = ensure(provider)
        products += [directory / 'manifest.json', directory / 'COPYRIGHT', loader(provider)]
        products += [directory / 'sysroot/usr/lib' / name for name in
                     ('libc.a', 'crt1.o', 'crti.o', 'crtn.o', 'Scrt1.o')]
    # The original libcap archive supplies every upstream source and License.
    from fetch import fetch
    products += [fetch('libcap')]
    records = {}
    for path in sources + products:
        name = path.relative_to(ROOT).as_posix()
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        records[name] = digest(destination)
    libraries = {}
    corresponding_source = None
    if native:
        for name in ('libc.so.6', 'ld-linux-x86-64.so.2', 'libc.a', 'libc_nonshared.a',
                     'crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'libgcc.a', 'crtbegin.o', 'crtend.o'):
            path = Path(subprocess.check_output(['gcc', '-print-file-name=' + name], text=True).strip()).resolve()
            if not path.is_file():
                raise RuntimeError('actual native linker input is missing: ' + name)
            destination = target / 'native-libraries' / name
            destination.parent.mkdir(exist_ok=True)
            shutil.copy2(path, destination)
            libraries[name] = dict(path=str(path), sha256=digest(path))
        gcc_major = subprocess.check_output(['gcc', '-dumpversion'], text=True).strip().split('.')[0]
        for package in ('libc6', 'libc6-dev', 'gcc-' + gcc_major + '-base', 'linux-libc-dev'):
            path = Path('/usr/share/doc') / package / 'copyright'
            destination = target / 'native-libraries' / (package + '-copyright')
            shutil.copy2(path, destination)
            libraries[package + '-copyright'] = dict(path=str(path), sha256=digest(path))
        for name in ('capability.h', 'xattr.h'):
            path = Path('/usr/include/linux') / name
            destination = target / 'native-libraries' / ('linux-' + name)
            shutil.copy2(path, destination)
            libraries['linux-' + name] = dict(path=str(path), sha256=digest(path))
        from file_capabilities.host_sources import capture
        corresponding_source = capture(target)
    save(output / 'inputs.json', dict(files=records, native_libraries=libraries,
          glibc_source=corresponding_source,
          native_dumpability=int(Path('/proc/sys/fs/suid_dumpable').read_text()) if native else None,
          compiler=subprocess.check_output(['gcc', '--version'], text=True),
          target=subprocess.check_output(['gcc', '-dumpmachine'], text=True).strip(),
          host=os.uname().release))

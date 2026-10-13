#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive normal administrator creation, Bash login, console recovery and ext2 reboots."""
import argparse
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time

from build_accounts import MODULES, digest, environment
from build_libxcrypt import ensure as password_library
from build_musl import compiler_args
from disk_root import archive_entries, bootstrap, populate
from fetch import ROOT
from qmp import Qmp

# This is a public, disposable test credential. Never use a person's password here.
PASSWORD = b'Fixture-normal-console-private-2026'
WRONG_PASSWORD = b'Fixture-intentionally-wrong-2026'
FILE_BYTES = b'Axiom64 authenticated persistent file\n'


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def build_observer(directory):
    library = password_library('build')
    stage = library / 'static/stage'
    program = directory / 'account-normal-observe'
    command = [*compiler_args('build'), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-static', '-I' + str(stage / 'usr/include'),
               *(str(ROOT / f'userspace/accounts/{name}.c') for name in MODULES),
               str(ROOT / 'userspace/tests/security/account-normal-observe.c'),
               '-o', str(program), str(stage / 'usr/lib/libcrypt.a')]
    with (directory / 'observer-build.log').open('wb') as log:
        subprocess.run(command, cwd=ROOT, env=environment(), check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    return program, dict(command=command, binary_sha256=digest(program),
                         library_manifest_sha256=digest(library / 'manifest.json'))


def build_desktop_observer(directory):
    program = directory / 'desktop-login-observe'
    command = [*compiler_args('build'), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-static', str(ROOT / 'userspace/tests/desktop/login-observe.c'),
               str(ROOT / 'userspace/desktop/authority.c'), '-o', str(program)]
    with (directory / 'desktop-observer-build.log').open('wb') as log:
        subprocess.run(command, cwd=ROOT, env=environment(), check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    return program, dict(command=command, binary_sha256=digest(program))


def write_cpio(destination, files):
    with destination.open('wb') as output:
        for inode, (name, (mode, payload)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(payload)
            output.write(bytes(-output.tell() % 4))


def image(directory, cpio, disk_root=False):
    name = directory.name + '.iso'
    command = ['python3', 'scripts/image.py', '--output-name', name]
    if disk_root:
        bootstrap(ROOT / 'build/rootfs-bootstrap.cpio')
        command += ['--root-device', '/dev/vda']
    else:
        command += ['--initramfs', str(cpio)]
    # No test flag: this must execute the installed normal PID1 path.
    with (directory / 'image-build.log').open('wb') as log:
        subprocess.run(command, cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
    result = directory / 'image.iso'
    shutil.copyfile(ROOT / 'build' / name, result)
    return result


def create_disk(destination, files):
    length = sum(len(payload) for mode, payload in files.values() if stat.S_ISREG(mode))
    unit = 64 * 1024 * 1024
    capacity = max(256 * 1024 * 1024, ((length * 2 + unit + unit - 1) // unit) * unit)
    with tempfile.TemporaryDirectory(prefix='axiom64-account-normal-') as temporary:
        stage = Path(temporary)
        populate(stage, files)
        with destination.open('wb') as output:
            output.truncate(capacity)
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '4096', '-I', '128',
                        '-O', 'none,filetype,sparse_super,large_file', '-N', str(len(files) + 4096),
                        '-E', 'lazy_itable_init=0,root_owner=0:0', '-d', str(stage), str(destination)],
                       check=True, capture_output=True)
    commands = [f'set_inode_field {json.dumps(name)} {field} 0'
                for name in ['/', '/lost+found', *('/' + name for name in sorted(files))]
                for field in ('uid', 'gid')]
    subprocess.run(['debugfs', '-w', '-f', '-', str(destination)], input='\n'.join(commands) + '\n',
                   check=True, capture_output=True, text=True)


def inspect(disk, directory, label):
    records = {}

    def metadata(name, mode, uid, gid, kind):
        result = subprocess.run(['debugfs', '-R', 'stat ' + name, str(disk)],
                                capture_output=True, text=True, check=True)
        (directory / (label + '-' + name.strip('/').replace('/', '-') + '-stat.log')).write_text(
            result.stdout + result.stderr)
        inode, actual_kind, actual_mode = re.search(
            r'Inode:\s+(\d+)\s+Type:\s+(\S+)\s+Mode:\s+([0-7]+)', result.stdout).groups()
        actual_uid, actual_gid, size = re.search(
            r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', result.stdout).groups()
        links = int(re.search(r'Links:\s+(\d+)', result.stdout)[1])
        assert (actual_kind, int(actual_mode, 8), int(actual_uid), int(actual_gid)) == (kind, mode, uid, gid)
        assert kind == 'directory' or links == 1
        records[name] = dict(inode=int(inode), kind=kind, mode=mode, uid=uid, gid=gid,
                             bytes=int(size), links=links)
        return result.stdout

    def payload(name):
        destination = directory / (label + '-' + name.strip('/').replace('/', '-') + '.bin')
        subprocess.run(['debugfs', '-R', 'dump ' + name + ' ' + str(destination), str(disk)],
                       capture_output=True, check=True)
        result = destination.read_bytes()
        assert PASSWORD not in result and WRONG_PASSWORD not in result
        records[name]['sha256'] = digest(destination)
        return result

    base = '/etc/axiom64/accounts'
    metadata(base, 0o755, 0, 0, 'directory')
    text = metadata(base + '/current', 0o777, 0, 0, 'symlink')
    target = re.search(r'Fast link dest:\s+"(g-[0-9a-f]{32})"', text)[1]
    contents = {}
    for name in ('passwd', 'group', 'shadow'):
        path = base + '/' + target + '/' + name
        metadata(path, 0o600 if name == 'shadow' else 0o644, 0, 0, 'regular')
        contents[name] = payload(path)
    assert b'admin:x:1000:1000:' in contents['passwd'] and b':/home/admin:/bin/bash\n' in contents['passwd']
    assert b'root:x:0:0:' in contents['passwd']
    assert b'sudo:x:27:admin\n' in contents['group']
    assert b'root:!:' in contents['shadow'] and b'admin:$y$' in contents['shadow']
    metadata('/home/admin', 0o700, 1000, 1000, 'directory')
    metadata('/home/admin/persisted-account', 0o600, 1000, 1000, 'regular')
    assert payload('/home/admin/persisted-account') == FILE_BYTES
    for name, mode in (('journal', 0o600), ('utmp', 0o644), ('wtmp', 0o644), ('btmp', 0o600), ('auth.log', 0o600)):
        path = '/var/log/axiom64/login/' + name
        metadata(path, mode, 0, 0, 'regular')
        data = payload(path)
        if name in ('utmp', 'wtmp', 'btmp'):
            assert len(data) % 384 == 0
        if name == 'journal':
            assert data and len(data) % 448 == 0
    fsck_log = directory / (label + '-fsck.log')
    with fsck_log.open('wb') as log:
        result = subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=log, stderr=subprocess.STDOUT)
    assert result.returncode == 0
    return dict(current=target, files=records, fsck_returncode=result.returncode,
                fsck_log_sha256=digest(fsck_log), disk_sha256=digest(disk))


def boot(directory, label, iso, firmware, fresh, disk=None, transport=None, graphical=False):
    control_directory = tempfile.TemporaryDirectory(prefix='axiom64-account-desktop-')
    control = Path(control_directory.name) / 'qmp.sock'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '1G', '-nic', 'none',
               '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if graphical:
        command += ['-qmp', f'unix:{control},server=on,wait=off']
    if disk:
        command += ['-drive', 'if=none,format=raw,cache=writeback,file=' + str(disk) + ',id=accounts',
                    '-device', 'virtio-blk-pci,drive=accounts,' +
                    ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = directory / (label + '-VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    started = time.monotonic()
    text, cursor, stage = bytearray(), 0, 'boot'
    log_path = directory / (label + '.log')
    log = log_path.open('wb')
    monitor = None
    captures, monitor_records, previous_desktop = [], [], []

    def monitor_command(name, arguments=None):
        nonlocal monitor
        if monitor is None:
            monitor = Qmp(control)
        result = monitor.command(name, arguments)
        monitor_records.append(dict(name=name, arguments=arguments, result=result))
        save(directory / (label + '-qmp.json'), monitor_records)
        return result

    def capture(blank=False):
        ppm = directory / f'{label}-screen-{len(captures)}.ppm'
        png = ppm.with_suffix('.png')
        monitor_command('screendump', dict(filename=str(ppm)))
        monitor_command('screendump', dict(filename=str(png), format='png'))
        magic, geometry, maximum, pixels = ppm.read_bytes().split(b'\n', 3)
        width, height = map(int, geometry.split())
        assert magic == b'P6' and maximum == b'255' and len(pixels) == width * height * 3
        different = sum(any(pixels[offset:offset + 3]) for offset in range(0, len(pixels), 3))
        assert different == 0 if blank else different > 100, 'actual framebuffer capture mismatch'
        captures.append(dict(ppm=ppm.name, ppm_sha256=digest(ppm), png=png.name,
            png_sha256=digest(png), width=width, height=height, nonblack_pixels=different, blank=blank))

    def keyboard(command):
        for character in command + '\n':
            code = {' ': 'spc', '/': 'slash', '-': 'minus', '\n': 'ret'}.get(character, character)
            monitor_command('send-key', dict(keys=[dict(type='qcode', data=code)], **{'hold-time': 30}))
            time.sleep(.07)

    def receive():
        ready, _, _ = select.select([process.stdout], [], [], 1)
        if ready:
            data = os.read(process.stdout.fileno(), 65536)
            log.write(data)
            log.flush()
            text.extend(data)
        assert PASSWORD not in text and WRONG_PASSWORD not in text, 'password appeared on serial'
        complete = text[:text.rfind(b'\n') + 1]
        failures = [line for line in complete.splitlines() if any(marker in line for marker in
            (b'ACCOUNT_NORMAL_FAIL', b'DESKTOP_LOGIN_FAIL', b'PANIC:', b'FAULT pid='))]
        if failures:
            raise AssertionError('actual guest check failed at ' + stage + ': ' +
                                 failures[-1].decode(errors='replace'))
        assert time.monotonic() - started < 180, 'normal boot deadline exceeded at ' + stage

    def until(marker):
        nonlocal cursor, stage
        stage, wanted = marker, marker.encode()
        while wanted not in text[cursor:]:
            receive()
            assert process.poll() is None or wanted in text[cursor:], 'VM exited before ' + marker
        cursor = text.index(wanted, cursor) + len(wanted)

    def send(value):
        process.stdin.write(value + b'\n')
        process.stdin.flush()

    def login(password=PASSWORD):
        until('login: ')
        if graphical:
            capture(blank=True)
        send(b'admin')
        until('Password: ')
        send(password)

    def identity():
        until('$ ')
        send(b'/usr/bin/account-normal-observe identity')
        until('ACCOUNT_NORMAL_IDENTITY_PASS ')
        until('$ ')

    def privileged(mode):
        send(b'sudo /usr/bin/account-normal-observe ' + mode)
        until('Password: ')
        send(PASSWORD)
        if mode != b'poweroff':
            until('ACCOUNT_NORMAL_PROTECTED_PASS ')
            until('$ ')

    def desktop():
        nonlocal previous_desktop
        send(b'/usr/bin/desktop-login-observe authorization')
        until('DESKTOP_AUTH_PASS valid=1 absent_denied=1 wrong_denied=1 rotated=')
        until('$ ')
        protected_command = 'sudo /usr/bin/desktop-login-observe protected'
        if previous_desktop:
            protected_command += ' ' + ' '.join(map(str, previous_desktop))
        send(protected_command.encode())
        until('Password: ')
        send(PASSWORD)
        if previous_desktop:
            until('DESKTOP_RETIRED_PASS processes=')
        until('ACCOUNT_NORMAL_PROTECTED_PASS ')
        until('DESKTOP_PROTECTED_PASS foreign_uid=1001')
        until('$ ')
        send(b'/bin/x11-probe --desktop')
        until('XTERM_WINDOW_ID window=')
        until('$ ')
        monitor_command('input-send-event', {'events': [
            {'type': 'rel', 'data': {'axis': 'x', 'value': 4}},
            {'type': 'rel', 'data': {'axis': 'y', 'value': 4}},
            {'type': 'btn', 'data': {'button': 'left', 'down': True}}]})
        monitor_command('input-send-event', {'events': [
            {'type': 'btn', 'data': {'button': 'left', 'down': False}}]})
        keyboard('/usr/bin/desktop-login-observe graphical')
        send(b'while ! test -f graphical-done; do sleep .1; done; /usr/bin/desktop-login-observe result')
        until('DESKTOP_KEYBOARD_IDENTITY_PASS uid=1000')
        until('$ ')
        capture()
        owner, server, clients = map(int, re.findall(
            rb'DESKTOP_PROTECTED_PASS [^\r\n]* owner=(\d+) server=(\d+) clients=(\d+)', text)[-1])
        beginning = list(re.finditer(rb'ACCOUNT_DESKTOP_READY uid=1000 server=\d+', text))[-1].start()
        descendants = [int(pid) for pid in re.findall(
            rb'exec pid=(\d+) /(?:usr/bin/(?:twm|xeyes|xterm)|bin/bash) ', text[beginning:])]
        previous_desktop = sorted(set([owner, server, clients, *descendants]))

    error = None
    try:
        if fresh:
            until('Administrator name: ')
            assert b'UID=0' not in text and b'root@' not in text
            send(b'admin')
            until('New password: ')
            send(PASSWORD)
            until('Confirm password: ')
            send(PASSWORD)
            until('Administrator created. Please log in.')
        login(WRONG_PASSWORD)
        until('Authentication failed.')
        login()
        identity()
        if graphical:
            desktop()
        assert text.count(b'Administrator created. Please log in.') == int(fresh)
        if not graphical:
            privileged(b'protected')
        console_pid = int(re.findall(rb'INIT_CONSOLE_SPAWN pid=(\d+) status=0', text)[-1])
        send(('sudo /bin/kill -KILL ' + str(console_pid)).encode())
        until('Password: ')
        send(PASSWORD)
        until('INIT_CONSOLE_REAP pid=' + str(console_pid) + ' status=9')
        login()
        identity()
        if not graphical:
            privileged(b'protected')
        if graphical:
            desktop()
            server = int(re.findall(rb'ACCOUNT_DESKTOP_READY uid=1000 server=(\d+)', text)[-1])
            send(('sudo /bin/kill -KILL ' + str(server)).encode())
            until('Password: ')
            send(PASSWORD)
            login()
            identity()
            desktop()
            keyboard('exit')
            login()
            identity()
            desktop()
        send(b'exit')
        login()
        identity()
        if graphical:
            desktop()
        if not graphical:
            privileged(b'protected')
        privileged(b'poweroff')
        until('AXIOM64_EXIT status=0')
        process.wait(timeout=30)
        assert process.returncode == 1
        assert 'Firmware: ' + firmware.upper() in text.decode(errors='replace')
        assert b'AXIOM64_TESTS_PASS' not in text and b'AXIOM64_TEST=1' not in text
        assert text.count(b'Administrator created. Please log in.') == int(fresh)
        if disk:
            assert b'VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0' in text
        events = [(event.decode(), int(pid), int(status), int(milliseconds)) for event, pid, status, milliseconds
                  in re.findall(rb'INIT_CONSOLE_(SPAWN|REAP) pid=(\d+) status=(\d+) monotonic_ms=(\d+)', text)]
        reaped = next(index for index, event in enumerate(events) if event[0] == 'REAP' and event[1] == console_pid)
        assert events[reaped + 1][0] == 'SPAWN' and events[reaped + 1][3] - events[reaped][3] >= 1000
        if graphical:
            assert text.count(b'DESKTOP_KEYBOARD_IDENTITY_PASS ') == 5
            assert text.count(b'DESKTOP_PROTECTED_PASS ') == 5
            assert text.count(b'DESKTOP_RETIRED_PASS ') == 4
            assert text.count(b'rotated=1') == 4 + int(disk is not None and not fresh)
            assert sum(capture['blank'] for capture in captures) == 6
    except Exception as caught:
        error = str(caught)
        if graphical and process.poll() is None:
            try:
                monitor_command('screendump', dict(filename=str(directory / (label + '-failure.png')),
                                                 format='png'))
            except Exception as capture_error:
                error += '; capture: ' + str(capture_error)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        if monitor:
            monitor.close()
        control_directory.cleanup()
        log.close()
        process.stdin.close()
        process.stdout.close()
    return dict(command=command, returncode=process.returncode, firmware=firmware, fresh=fresh,
                transport=transport, elapsed_seconds=time.monotonic() - started,
                log_sha256=digest(log_path), passed=error is None, error=error, stage=stage,
                graphical=graphical, captures=captures, monitor_records=len(monitor_records))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/account-normal')
    parser.add_argument('--profile', choices=('desktop', 'full'), default='desktop')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'all'), default='all')
    parser.add_argument('--storage', choices=('ram', 'ext2', 'all'), default='all')
    parser.add_argument('--graphical', action='store_true',
                        help='verify real cookie denial, X11 pixels, keyboard identity and seat recovery')
    args = parser.parse_args()
    directory = args.directory.resolve()
    assert directory.is_relative_to((ROOT / 'build').resolve())
    directory.mkdir(parents=True, exist_ok=False)
    rootfs = ROOT / 'build' / ('rootfs-desktop.cpio' if args.profile == 'desktop' else 'rootfs.cpio')
    subprocess.run(['make', '-s', '-j2', str(rootfs.relative_to(ROOT)), 'build/axiom64.elf'], cwd=ROOT, check=True)
    names = [str(path.relative_to(ROOT)) for parent in ('kernel', 'userspace', 'scripts')
             for path in (ROOT / parent).rglob('*') if path.is_file() and path.suffix in
             ('.cpp', '.hpp', '.asm', '.c', '.h', '.sh', '.py')]
    names += ['Makefile', 'sources.lock.json', 'ports.lock.json', 'dependencies.json', 'boot/limine.conf']
    source = {name: digest(ROOT / name) for name in names}
    save(directory / 'source-inputs.json', source)
    program, inputs = build_observer(directory)
    files = archive_entries(rootfs)
    files['usr/bin/account-normal-observe'] = (0o100755, program.read_bytes())
    if args.graphical:
        graphical_program, graphical_inputs = build_desktop_observer(directory)
        files['usr/bin/desktop-login-observe'] = (0o100755, graphical_program.read_bytes())
        inputs['desktop_observer'] = graphical_inputs
    cpio = directory / 'root.cpio'
    write_cpio(cpio, files)
    inputs.update(normal_cpio_sha256=digest(rootfs), root_cpio_sha256=digest(cpio),
                  kernel_sha256=digest(ROOT / 'build/axiom64.elf'), profile=args.profile)
    save(directory / 'inputs.json', inputs)
    rows = []
    firmware_values = ('bios', 'uefi') if args.firmware == 'all' else (args.firmware,)
    if args.storage in ('ram', 'all'):
        iso = image(directory, cpio)
        inputs['ram_image_sha256'] = digest(iso)
        for firmware in firmware_values:
            row = boot(directory, 'ram-' + firmware, iso, firmware, True, graphical=args.graphical)
            rows.append(row)
            save(directory / 'results.json', rows)
            assert row['passed'], row
            print('ACCOUNT_NORMAL_RAM_PASS ' + firmware, flush=True)
    if args.storage in ('ext2', 'all'):
        disk_images = directory / 'disk-image'
        disk_images.mkdir()
        iso = image(disk_images, cpio, True)
        inputs['disk_image_sha256'] = digest(iso)
        for firmware in firmware_values:
            for transport in ('modern', 'legacy'):
                label = firmware + '-' + transport
                case = directory / label
                case.mkdir()
                disk = case / 'root.ext2'
                create_disk(disk, files)
                previous = None
                for fresh in (True, False):
                    phase = 'create' if fresh else 'reboot'
                    row = boot(case, phase, iso, firmware, fresh, disk, transport, args.graphical)
                    rows.append(row)
                    save(directory / 'results.json', rows)
                    assert row['passed'], row
                    row['host_state'] = inspect(disk, case, phase)
                    if previous:
                        assert previous['current'] == row['host_state']['current']
                        stable = ['/home/admin', '/home/admin/persisted-account', '/etc/axiom64/accounts/current']
                        stable += ['/etc/axiom64/accounts/' + previous['current'] + '/' + name
                                   for name in ('passwd', 'group', 'shadow')]
                        assert all(previous['files'][name] == row['host_state']['files'][name] for name in stable)
                    previous = row['host_state']
                    save(directory / 'results.json', rows)
                print('ACCOUNT_NORMAL_EXT2_REBOOT_PASS ' + label, flush=True)
    save(directory / 'inputs.json', inputs)
    assert source == {name: digest(ROOT / name) for name in source}
    print('ACCOUNT_NORMAL_MATRIX_PASS boots=' + str(len(rows)), flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify seed supervision and crypto tools through ordinary init and serial shells."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time

from disk_root import archive_entries, build
from fetch import ROOT
from random_administration_test import copy_executable, fingerprint, snapshot
from random_crypto.inputs import provider
from random_installed_records import seed_records
from normal_login import ConsoleLogin, install_observer
from account_normal_test import PASSWORD, write_cpio
from build_musl import compiler_args
from build_accounts import environment
from fixture_archive import archive_fixture

SEED = '/var/lib/axiom64/random'
MESSAGE = b'Axiom64 installed seed service\n'


def record(text, name):
    found = re.findall(r'^INSTALLED_RANDOM_' + name + r' ([^\n]+)\n', text, re.MULTILINE)
    if len(found) != 1:
        raise RuntimeError('missing or repeated installed observation: ' + name)
    return found[0]


def inspect_disk(disk, directory):
    results = {}
    for name, mode, size in (('seed', '0600', 32), ('lock', '0600', 0)):
        path = SEED + '/' + name
        command = ['debugfs', '-R', 'stat ' + path, str(disk)]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        (directory / (name + '-stat.log')).write_text(result.stdout + result.stderr)
        inode = re.search(r'Inode:\s+(\d+)\s+Type:\s+regular\s+Mode:\s+([0-7]+)', result.stdout)
        identity = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+).*?Size:\s+(\d+)', result.stdout)
        links = re.search(r'Links:\s+(\d+)', result.stdout)
        if (not inode or not identity or not links or int(inode[2], 8) != int(mode, 8) or
                tuple(map(int, identity.groups())) != (0, 0, size) or int(links[1]) != 1):
            raise RuntimeError('independent installed seed metadata differs: ' + name)
        exported = directory / (name + '.bin')
        subprocess.run(['debugfs', '-R', 'dump ' + path + ' ' + str(exported), str(disk)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        if exported.stat().st_size != size:
            raise RuntimeError('independent installed file length differs')
        results[name] = dict(inode=int(inode[1]), mode=int(mode, 8), uid=0, gid=0,
                             size=size, links=1, payload=fingerprint(exported))
    with (directory / 'fsck.log').open('wb') as stream:
        checked = subprocess.run(['e2fsck', '-f', '-n', str(disk)], stdout=stream,
                                 stderr=subprocess.STDOUT)
    if checked.returncode:
        raise RuntimeError('the installed root failed the independent filesystem check')
    results['fsck'] = dict(returncode=checked.returncode, log=fingerprint(directory / 'fsck.log'))
    results['disk'] = fingerprint(disk)
    return results


def shell_check(ready):
    lines = ['set -eu', f'test "$(stat -c %a:%u:%g {SEED})" = 700:0:0']
    if ready:
        lines += [f'test "$(stat -c %a:%u:%g:%s:%h {SEED}/seed)" = 600:0:0:32:1',
                  f'test "$(stat -c %a:%u:%g:%s:%h {SEED}/lock)" = 600:0:0:0:1',
                  'openssl version', 'openssl rand -out /tmp/installed-random.bin 32',
                  'test "$(wc -c < /tmp/installed-random.bin)" -eq 32',
                  "printf 'Axiom64 installed seed service\\n' > /tmp/installed-message",
                  'openssl genpkey -algorithm ED25519 -out /tmp/installed.key',
                  'openssl pkey -in /tmp/installed.key -pubout -outform DER -out /tmp/installed.der',
                  'openssl pkeyutl -sign -rawin -inkey /tmp/installed.key '
                  '-in /tmp/installed-message -out /tmp/installed.sig',
                  "printf '%s%s %s\\n' INSTALLED_RANDOM_ PUBLIC "
                  '"$(openssl base64 -A -in /tmp/installed.der)"',
                  "printf '%s%s %s\\n' INSTALLED_RANDOM_ SIGNATURE "
                  '"$(openssl base64 -A -in /tmp/installed.sig)"',
                  "printf '%s%s %s\\n' INSTALLED_RANDOM_ SEED "
                  f'"$(od -An -v -tx1 {SEED}/seed | tr -d \' \\n\')"']
    else:
        lines += [f'test ! -e {SEED}/seed']
    lines += ["printf '%s%s %s\\n' INSTALLED_RANDOM_ CHECK " + ('ready' if ready else 'unready')]
    return (shlex.join(['/bin/busybox', 'sh', '-c', '\n'.join(lines)]) + '\n').encode()


def unready_observer(directory):
    program = directory / 'random-installed-unready'
    command = [*compiler_args('build'), '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-static', str(ROOT / 'userspace/tests/security/random-installed-unready.c'),
               '-o', str(program)]
    with (directory / 'unready-build.log').open('wb') as log:
        subprocess.run(command, cwd=ROOT, env=environment(), check=True,
                       stdout=log, stderr=subprocess.STDOUT)
    return program, dict(command=command, binary=fingerprint(program))


def verify_signature(directory, text, observer):
    for label in ('PUBLIC', 'SIGNATURE'):
        value = base64.b64decode(record(text, label), validate=True)
        if not value or len(value) > 4096:
            raise RuntimeError('invalid installed crypto export')
        (directory / (label.lower() + '.bin')).write_bytes(value)
    message = directory / 'message.bin'
    message.write_bytes(MESSAGE)
    command = [str(observer), 'pkey', '-pubin', '-inform', 'DER', '-in',
               str(directory / 'public.bin'), '-out', str(directory / 'public.pem')]
    with (directory / 'signature-check.log').open('wb') as stream:
        subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True)
        command = [str(observer), 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey',
                   str(directory / 'public.pem'), '-sigfile', str(directory / 'signature.bin'), '-in']
        valid = subprocess.run(command + [str(message)], stdout=stream, stderr=subprocess.STDOUT)
        tampered = directory / 'tampered.bin'
        tampered.write_bytes(MESSAGE + b'tampered\n')
        invalid = subprocess.run(command + [str(tampered)], stdout=stream, stderr=subprocess.STDOUT)
    if valid.returncode != 0 or invalid.returncode == 0:
        raise RuntimeError('independent installed signature acceptance failed')
    return dict(public=fingerprint(directory / 'public.bin'),
                signature=fingerprint(directory / 'signature.bin'),
                valid_returncode=valid.returncode, tampered_returncode=invalid.returncode,
                log=fingerprint(directory / 'signature-check.log'))


def boot(directory, iso, firmware, transport, ready, observer, disk=None, previous=None):
    directory.mkdir()
    log = directory / 'guest.log'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu',
               'max' if ready else 'max,rdseed=off,rdrand=off', '-m', '2G', '-nic', 'none',
               '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot']
    if disk:
        command += ['-drive', f'if=none,id=root,format=raw,cache=writeback,file={disk}',
                    '-device', 'virtio-blk-pci,drive=root,' +
                    ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if firmware == 'uefi':
        variables = directory / 'VARS.fd'
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
    started = time.monotonic_ns()
    row = dict(firmware=firmware, transport=transport, ready=ready, root='ext2' if disk else 'ramfs',
               command=command, image=fingerprint(iso), passed=False)
    process = None
    try:
        with log.open('wb') as stream:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stream,
                                       stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 180
            def console_write(value):
                process.stdin.write(value)
                process.stdin.flush()
            login = ConsoleLogin(console_write)

            def wait(predicate):
                while time.monotonic() < deadline:
                    text = log.read_text()
                    login.consume(text)
                    if any(marker in text for marker in ('PANIC:', 'FAULT pid=', 'BOOT_ROOT_FAIL',
                                                         'INSTALLED_RANDOM_FAIL', 'ACCOUNT_NORMAL_FAIL')):
                        raise RuntimeError('the ordinary installed boot reported a fault')
                    if predicate(text):
                        return text
                    if process.poll() is not None:
                        raise RuntimeError('the ordinary installed boot ended before its observation')
                    time.sleep(.02)
                raise TimeoutError('ordinary seed service observation expired')

            if ready:
                wait(lambda text: login.ready)
                login.command(b"/usr/bin/account-normal-observe identity && "
                              b"printf '%s%s\\n' INSTALLED_RANDOM_ CONSOLE\n")
                wait(lambda text: '\nINSTALLED_RANDOM_CONSOLE\n' in text)
                wait(lambda text: any(row[1] == '0' for row in seed_records(text, 'REAP')))
                login.elevate(shell_check(True).decode().strip())
            else:
                wait(lambda text: sum(row[1] == '256' for row in seed_records(text, 'REAP')) >= 3)
            text = wait(lambda text: '\nINSTALLED_RANDOM_CHECK ' + ('ready' if ready else 'unready') + '\n' in text)
            spawn = seed_records(text, 'SPAWN')
            reaped = seed_records(text, 'REAP')
            if not spawn or not reaped or (ready and (len(spawn) != 1 or len(reaped) != 1)):
                raise RuntimeError('the actual init seed ownership records are incomplete')
            for index, (pid, status, when) in enumerate(reaped):
                if pid != spawn[index][0] or int(status) != (0 if ready else 256):
                    raise RuntimeError('the actual init child status or ownership differs')
                if index + 1 < len(spawn) and int(spawn[index+1][1]) - int(when) < 1000:
                    raise RuntimeError('init retried the seed service before one real second')
            row.update(spawns=spawn, reaps=reaped, login_events=login.events)
            if ready:
                seed = bytes.fromhex(record(text, 'SEED'))
                if len(seed) != 32 or (previous is not None and seed == previous):
                    raise RuntimeError('the installed service did not rotate a complete fresh seed')
                row['seed_sha256'] = hashlib.sha256(seed).hexdigest()
                row['crypto'] = verify_signature(directory, text, observer)
                (directory / 'guest-seed.bin').write_bytes(seed)
                login.elevate('/bin/busybox poweroff -f')
                wait(lambda text: 'PLATFORM_POWEROFF method=piix4\n' in text)
            elif (text.count('RANDOM_SEED_FAILED stage=initialized-output error=11\n') < 3 or
                  'RANDOM_READY ' in text or 'RANDOM_SEED_ROTATED ' in text):
                raise RuntimeError('an unready ordinary boot returned initialized data')
            else:
                if (login.ready or login.events != ['administrator', 'new', 'confirm'] or
                        'Administrator created.' in text or 'ACCOUNT_DESKTOP_READY ' in text or
                        'INSTALLED_RANDOM_UNREADY_OBSERVER private_directory=1 seed_absent=1 '
                        'initialized_denied=1 accounts_unpublished=1 x11_absent=1 observation_seconds=8\n' not in text):
                    raise RuntimeError('entropy-unready provisioning must remain blocked')
            process.wait(timeout=max(.01, deadline-time.monotonic()))
        text = log.read_text()
        row['guest_elapsed_ns'] = time.monotonic_ns() - started
        if PASSWORD.decode() in text:
            raise RuntimeError('fixture password appeared in installed seed capture')
        if process.returncode != 0 or 'PLATFORM_POWEROFF method=piix4\n' not in text:
            raise RuntimeError('the ordinary installed boot did not shut down cleanly')
        if disk:
            row['filesystem'] = inspect_disk(disk, directory)
            if (directory / 'seed.bin').read_bytes() != (directory / 'guest-seed.bin').read_bytes():
                raise RuntimeError('persisted seed differs from the actual serial export')
            retained = archive_fixture(disk, owned_root=directory.parent)
            if retained['original'] != row['filesystem']['disk']:
                raise RuntimeError('the retained installed disk checkpoint differs')
            shutil.move(retained['path'], directory / 'root.raw.gz')
            retained['path'] = str(directory / 'root.raw.gz')
            row['retained_disk'] = retained
        row['passed'] = True
    except BaseException as error:
        row['error'] = repr(error)
        raise
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        if process is not None:
            process.stdin.close()
        row.update(returncode=process.returncode if process else None,
                   elapsed_ns=time.monotonic_ns()-started)
        if log.exists():
            row['log'] = fingerprint(log)
        (directory / 'result.json').write_text(json.dumps(row, indent=2)+'\n')
    print(json.dumps(dict(case=directory.name, passed=True)), flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('full', 'desktop', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--root', choices=('ram', 'ext2', 'both'), default='both')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-installed-results')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    observer_dir, _ = provider('build')
    observer = out / 'observer-openssl'
    copy_executable(observer_dir / 'static/stage/usr/bin/openssl', observer)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/rootfs.cpio',
                    'build/rootfs-desktop.cpio'], cwd=ROOT, check=True)
    inputs = snapshot(out)
    for name in ('userspace/init/main.c', 'userspace/init/console.c', 'userspace/init/console.h',
                 'userspace/init/seed_records.h', 'userspace/services/random_seed.c',
                 'scripts/random_installed_records.py', 'scripts/rootfs.py',
                 'scripts/disk_root.py', 'scripts/image.py', 'scripts/random_installed_test.py',
                 'scripts/normal_login.py', 'scripts/account_normal_test.py',
                 'scripts/console_prompt.py',
                 'scripts/fixture_archive.py',
                 'userspace/tests/security/account-normal-observe.c',
                 'userspace/tests/security/random-installed-unready.c'):
        inputs[name] = fingerprint(ROOT / name)
    (out / 'source-inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    unready_program, unready_inputs = unready_observer(out)
    (out / 'unready-inputs.json').write_text(json.dumps(unready_inputs, indent=2)+'\n')
    results = []
    for profile in ('full', 'desktop') if args.profile == 'both' else (args.profile,):
        source = ROOT / 'build' / ('rootfs.cpio' if profile == 'full' else 'rootfs-desktop.cpio')
        entries = archive_entries(source)
        if entries['sbin/random-seed'][1] != (ROOT / 'build/random-seed-static').read_bytes():
            raise RuntimeError('ordinary profile contains a different seed service')
        if entries['var/lib/axiom64/random'][0] != 0o40700:
            raise RuntimeError('ordinary profile has unsafe seed directory permissions')
        shutil.copyfile(source, out / (profile + '.cpio'))
        fixture = out / (profile + '-fixture')
        fixture.mkdir()
        observer_inputs = install_observer(entries, fixture)
        (fixture / 'observer-inputs.json').write_text(json.dumps(observer_inputs, indent=2)+'\n')
        ready_cpio = fixture / 'ready.cpio'
        write_cpio(ready_cpio, entries)
        unready_entries = entries.copy()
        unready_entries['sbin/network-manager-installed'] = entries['sbin/network-manager']
        unready_entries['sbin/network-manager'] = (0o100755, unready_program.read_bytes())
        unready_cpio = fixture / 'unready.cpio'
        write_cpio(unready_cpio, unready_entries)
        for archive in (ready_cpio, unready_cpio):
            installed = archive_entries(archive)
            for name in ('sbin/init', 'sbin/random-seed', 'sbin/account-console', 'usr/bin/account-access'):
                if installed[name] != entries[name]:
                    raise RuntimeError('seed fixture changed a production authentication or seed program')
        base = None
        if args.root != 'ram':
            generated = build(profile, source=ready_cpio)
            base = fixture / 'seed.raw'
            shutil.copyfile(generated, base)
            (fixture / 'seed-input.json').write_text(json.dumps(fingerprint(base), indent=2) + '\n')
        for root in ('ram', 'ext2') if args.root == 'both' else (args.root,):
            for ready in (True, False) if root == 'ram' else (True,):
                label = profile + '-' + root + ('-ready' if ready else '-unready')
                name = 'axiom64-random-installed-' + label + '.iso'
                command = ['python3', 'scripts/image.py', '--output-name', name]
                command += (['--root-device', '/dev/vda'] if root == 'ext2' else
                            ['--initramfs', str(ready_cpio if ready else unready_cpio)])
                if not ready:
                    command += ['--kernel-option', 'random.trust_cpu=off']
                with (out / (label + '-image.log')).open('wb') as stream:
                    subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, check=True)
                iso = out / name
                shutil.copyfile(ROOT / 'build' / name, iso)
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    for transport in (('none',) if root == 'ram' else
                                      (('modern', 'legacy') if args.transport == 'both' else (args.transport,))):
                        case = label + '-' + firmware + '-' + transport
                        disk = out / (case + '.raw') if root == 'ext2' else None
                        if disk:
                            shutil.copyfile(base, disk)
                        previous = None
                        for boot_number in range(2 if disk else 1):
                            folder = out / (case + '-' + str(boot_number))
                            row = boot(folder, iso, firmware, transport, ready, observer, disk, previous)
                            row.update(profile=profile, boot=boot_number)
                            results.append(row)
                            (out / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
                            if disk:
                                previous = (folder / 'guest-seed.bin').read_bytes()
                        if disk:
                            retained = results[-1]['retained_disk']['original']
                            if disk.is_symlink() or disk.resolve().parent != out or fingerprint(disk) != retained:
                                raise RuntimeError('working seed disk differs from its verified retained checkpoint')
                            disk.unlink()
    if inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('the installed seed sources changed during acceptance')


if __name__ == '__main__':
    main()

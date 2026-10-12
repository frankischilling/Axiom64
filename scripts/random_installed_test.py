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

SEED = '/var/lib/axiom64/random'
MESSAGE = b'Axiom64 installed seed service\n'


def seed_records(text, event):
    status = r' status=(\d+)' if event == 'REAP' else ''
    return re.findall(r'^(?:/ # )?INIT_RANDOM_SEED_' + event + r' pid=(\d+)' + status +
                      r' monotonic_ms=(\d+)\r?\n', text, re.MULTILINE)


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

            def wait(predicate):
                while time.monotonic() < deadline:
                    text = log.read_text()
                    if any(marker in text for marker in ('PANIC:', 'FAULT pid=', 'BOOT_ROOT_FAIL')):
                        raise RuntimeError('the ordinary installed boot reported a fault')
                    if predicate(text):
                        return text
                    if process.poll() is not None:
                        raise RuntimeError('the ordinary installed boot ended before its observation')
                    time.sleep(.02)
                raise TimeoutError('ordinary seed service observation expired')

            wait(lambda text: 'Axiom64. Starting Xorg' in text)
            process.stdin.write(b"printf '%s%s\\n' INSTALLED_RANDOM_ CONSOLE\n")
            process.stdin.flush()
            wait(lambda text: '\nINSTALLED_RANDOM_CONSOLE\n' in text)
            if ready:
                wait(lambda text: any(row[1] == '0' for row in seed_records(text, 'REAP')))
            else:
                wait(lambda text: sum(row[1] == '256' for row in seed_records(text, 'REAP')) >= 3)
            process.stdin.write(shell_check(ready))
            process.stdin.flush()
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
            row.update(spawns=spawn, reaps=reaped)
            if ready:
                seed = bytes.fromhex(record(text, 'SEED'))
                if len(seed) != 32 or (previous is not None and seed == previous):
                    raise RuntimeError('the installed service did not rotate a complete fresh seed')
                row['seed_sha256'] = hashlib.sha256(seed).hexdigest()
                row['crypto'] = verify_signature(directory, text, observer)
                (directory / 'guest-seed.bin').write_bytes(seed)
            elif (text.count('RANDOM_SEED_FAILED stage=initialized-output error=11\n') < 3 or
                  'RANDOM_READY ' in text or 'RANDOM_SEED_ROTATED ' in text):
                raise RuntimeError('an unready ordinary boot returned initialized data')
            process.stdin.write(b'/bin/busybox poweroff -f\n')
            process.stdin.flush()
            process.wait(timeout=max(.01, deadline-time.monotonic()))
        text = log.read_text()
        if process.returncode != 0 or 'PLATFORM_POWEROFF method=piix4\n' not in text:
            raise RuntimeError('the ordinary installed boot did not shut down cleanly')
        if disk:
            row['filesystem'] = inspect_disk(disk, directory)
            if (directory / 'seed.bin').read_bytes() != (directory / 'guest-seed.bin').read_bytes():
                raise RuntimeError('persisted seed differs from the actual serial export')
            shutil.copyfile(disk, directory / 'root.raw')
            if fingerprint(directory / 'root.raw') != row['filesystem']['disk']:
                raise RuntimeError('the retained installed disk checkpoint differs')
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
    for name in ('userspace/init/main.c', 'userspace/services/random_seed.c', 'scripts/rootfs.py',
                 'scripts/disk_root.py', 'scripts/image.py', 'scripts/random_installed_test.py'):
        inputs[name] = fingerprint(ROOT / name)
    (out / 'source-inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    results = []
    for profile in ('full', 'desktop') if args.profile == 'both' else (args.profile,):
        source = ROOT / 'build' / ('rootfs.cpio' if profile == 'full' else 'rootfs-desktop.cpio')
        entries = archive_entries(source)
        if entries['sbin/random-seed'][1] != (ROOT / 'build/random-seed-static').read_bytes():
            raise RuntimeError('ordinary profile contains a different seed service')
        if entries['var/lib/axiom64/random'][0] != 0o40700:
            raise RuntimeError('ordinary profile has unsafe seed directory permissions')
        shutil.copyfile(source, out / (profile + '.cpio'))
        base = build(profile) if args.root != 'ram' else None
        for root in ('ram', 'ext2') if args.root == 'both' else (args.root,):
            for ready in (True, False) if root == 'ram' else (True,):
                label = profile + '-' + root + ('-ready' if ready else '-unready')
                name = 'axiom64-random-installed-' + label + '.iso'
                command = ['python3', 'scripts/image.py', '--output-name', name]
                command += ['--root-device', '/dev/vda'] if root == 'ext2' else ['--initramfs', str(source)]
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
    if inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('the installed seed sources changed during acceptance')


if __name__ == '__main__':
    main()

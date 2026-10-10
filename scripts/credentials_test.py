# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the native-tested identity and permission client on RAM and ext2 guests."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from fetch import ROOT, LOCK


def fixture(linkage, filesystem):
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init',
                    f'build/credentials-{linkage}', 'busybox'], cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    if version != expected:
        raise RuntimeError('credential fixture musl differs from the pinned build version')
    files = {name: (0o40755, b'') for name in ['bin', 'sbin', 'lib', 'etc', 'dev', 'proc', 'tmp', 'run']}
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         ('bin/credentials-tests', ROOT / 'build' / f'credentials-{linkage}'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve())]:
        files[name] = (0o100755, source.read_bytes())
    script = '#!/bin/sh\nset -e\n'
    if filesystem == 'ext2':
        script += '/bin/busybox mount -t ext2 /dev/vda /tmp\n'
    script += ('CREDENTIAL_POLICY_MOUNT=/tmp ' if filesystem == 'ext2' else '')
    script += f'/bin/credentials-tests{" --keep-owner" if filesystem == "ext2" else ""}\n'
    if filesystem == 'ext2':
        script += '/bin/busybox umount /tmp\n'
        script += '/bin/busybox mount -t ext2 /dev/vda /tmp\n'
        script += '/bin/credentials-tests --verify-owner\n'
        script += '/bin/busybox umount /tmp\n'
    script += 'echo AXIOM64_TESTS_PASS\n'
    files['etc/net-test.sh'] = (0o100755, script.encode())
    with (ROOT / 'build/rootfs-network.cpio').open('wb') as output:
        for inode, (name, (mode, data)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    image = ROOT / 'build' / f'axiom64-credentials-{linkage}-{filesystem}.iso'
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', image.name], cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    return image


def run(linkage, filesystem, firmware, timeout, image):
    label = f'credentials-{linkage}-{filesystem}-{firmware}'
    log = ROOT / 'build' / (label + '.log')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M', '-nic', 'none',
               '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    disk = None
    if filesystem == 'ext2':
        disk = ROOT / 'build' / (label + '.img')
        with disk.open('wb') as output:
            output.truncate(64 * 1024 * 1024)
        subprocess.run(['mke2fs', '-q', '-t', 'ext2', '-b', '1024', '-I', '128', '-F', str(disk)], check=True)
        command += ['-drive', f'if=none,format=raw,file={disk},id=credentials',
                    '-device', 'virtio-blk-pci,drive=credentials,disable-legacy=on']
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started, timed_out = time.monotonic(), False
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
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
    required = ['CREDENTIAL_IDS_PASS ', 'CREDENTIAL_THREADS_PASS ', 'CREDENTIAL_DAC_PASS ',
                'CREDENTIAL_CAPS_PASS ', 'CREDENTIAL_SHM_PASS ', 'CREDENTIAL_UNIX_PASS ',
                'CREDENTIAL_EXEC_PASS ', 'CREDENTIAL_PATH_PASS ', 'CREDENTIAL_SIGNAL_PASS ',
                'CREDENTIAL_MOUNT_PASS ', f'CREDENTIAL_TEST_PASS linkage={linkage}',
                'CREDENTIAL_CAP_EXEC_PASS ', 'CREDENTIAL_INTERPRETER_PASS ',
                'CREDENTIAL_NETWORK_PASS ',
                'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', f'Firmware: {firmware.upper()}']
    missing = [marker for marker in required if marker not in text]
    services = 3 + (filesystem == 'ext2') + (linkage == 'dynamic')
    if text.count('CREDENTIAL_SERVICE_PASS actual_exec irreversible_drop') != services:
        missing.append('all actual set-ID, no-new-privileges and nosuid exec services')
    if text.count('CREDENTIAL_CAP_SERVICE_PASS ') != 3 or text.count('CREDENTIAL_GROUP_SERVICE_PASS ') != 2:
        missing.append('all actual ambient/bounding/setgid exec services')
    host = {}
    if disk and not timed_out and process.returncode == 1 and not missing:
        if 'CREDENTIAL_REMOUNT_PASS decoded_full_width_owner permission_checks' not in text:
            missing.append('fresh remount decodes and enforces full-width inode owner')
        check = subprocess.run(['e2fsck', '-fn', str(disk)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        stat = subprocess.run(['debugfs', '-R', 'stat /persisted-owner', str(disk)], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
        (ROOT / 'build' / (label + '-fsck.log')).write_text(check.stdout)
        (ROOT / 'build' / (label + '-inode.log')).write_text(stat.stdout)
        host = dict(fsck=check.returncode, inode=stat.returncode)
        if check.returncode or stat.returncode or not re.search(r'User:\s+65537\s+Group:\s+131073', stat.stdout):
            missing.append('independent clean ext2 and persisted full-width UID/GID')
        if 'CREDENTIAL_PERSIST_PASS uid=65537 gid=131073 mode=0640' not in text:
            missing.append('guest full-width persistent inode owner')
    result = dict(linkage=linkage, filesystem=filesystem, firmware=firmware, returncode=process.returncode,
                  timed_out=timed_out, missing=missing, host=host, log=log.name,
                  seconds=round(time.monotonic() - started, 3),
                  passed=not timed_out and process.returncode == 1 and not missing and not any(
                      marker in text for marker in ('CREDENTIAL_TEST_FAIL ', 'PANIC:', 'FAULT pid=')))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-5000:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--filesystem', choices=('ramfs', 'ext2'), nargs='+', default=['ramfs', 'ext2'])
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=120)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results = []
    original = ROOT / 'build/rootfs-network.cpio'
    previous = original.read_bytes() if original.exists() else None
    try:
        for linkage in ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,):
            for filesystem in args.filesystem:
                image = fixture(linkage, filesystem)
                for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                    result = run(linkage, filesystem, firmware, args.timeout, image)
                    results.append(result)
                    (ROOT / 'build/credentials-results.json').write_text(json.dumps(results, indent=2) + '\n')
                    if not result['passed']:
                        raise SystemExit('Guest credentials and permissions failed')
    finally:
        if previous is not None:
            original.write_bytes(previous)
        elif original.exists():
            original.unlink()


if __name__ == '__main__':
    main()

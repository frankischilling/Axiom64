"""Verify static/dynamic saved-file policy on guest RAM and disposable ext2 volumes."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
from fetch import ROOT, LOCK
from ext2_test import SEED, create_volume, check_fs, dump


def fixture(volume):
    subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    'build/abi-static', 'build/abi-dynamic',
                    'build/profile-privacy-tests', 'build/profile-privacy-dynamic'],
                   cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    if version != expected:
        raise RuntimeError('fixture musl differs from the pinned build version')
    files = {name: (0o40755, b'') for name in
             ['bin', 'sbin', 'etc', 'dev', 'proc', 'sys', 'tmp', 'run', 'root', 'lib', 'data']}
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('bin/profile-privacy-tests', ROOT / 'build/profile-privacy-tests'),
                         ('bin/profile-privacy-dynamic', ROOT / 'build/profile-privacy-dynamic'),
                         ('bin/abi-static', ROOT / 'build/abi-static'),
                         ('bin/abi-dynamic', ROOT / 'build/abi-dynamic'),
                         ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve())]:
        files[name] = (0o100755, Path(source).read_bytes())
    script = (ROOT / 'userspace/tests/net/profile-privacy.sh').read_bytes()
    files['etc/net-test.sh'] = (0o100755, f'export PROFILE_VOLUME={volume}\n'.encode() + script)
    files['etc/profile-seed'] = (0o100644, SEED)
    with (ROOT / 'build/rootfs-network.cpio').open('wb') as output:
        entries = [*sorted(files.items()), ('TRAILER!!!', (0, b''))]
        for inode, (name, (mode, data)) in enumerate(entries, 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', f'axiom64-profile-{volume}.iso'], cwd=ROOT, check=True)


def run(volume, firmware, transport, timeout):
    label = f'profile-{volume}-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    mode = 'disable-legacy=on' if transport == 'modern' else 'disable-modern=on'
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
               '-cdrom', str(ROOT / 'build' / f'axiom64-profile-{volume}.iso'), '-nic', 'none',
               '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-netdev', 'user,id=first,restrict=on',
               '-device', f'virtio-net-pci,netdev=first,addr=4,mac=52:54:00:12:34:10,{mode}',
               '-netdev', 'user,id=second,restrict=on',
               '-device', 'e1000,netdev=second,addr=5,mac=52:54:00:12:34:11']
    disk = ROOT / 'build' / (label + '.raw')
    if volume == 'ext2':
        create_volume(disk)
        command += ['-drive', f'if=none,id=saved,format=raw,cache=writeback,file={disk}',
                    '-device', f'virtio-blk-pci,drive=saved,addr=6,{mode},rerror=report,werror=report']
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text(errors='replace')
    markers = ['PROFILE_PRIVACY_FILES_PASS', 'PROFILE_PRIVACY_ANCESTORS_UMASK_PASS',
               'PROFILE_PRIVACY_FAILURES_PASS',
               'PROFILE_PRIVACY_TESTS_PASS linkage=static uid=0',
               'PROFILE_PRIVACY_TESTS_PASS linkage=dynamic uid=0',
               'ABI_RELATIVE_MODES_PASS linkage=static',
               'ABI_RELATIVE_MODES_PASS linkage=dynamic',
               'ABI_TESTS_PASS linkage=static', 'ABI_TESTS_PASS linkage=dynamic',
               f'PROFILE_PRIVACY_VOLUME_PASS volume={volume}',
               f'Firmware: {firmware.upper()}', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    if volume == 'ext2':
        markers += ['PROFILE_PRIVACY_UNMOUNT_PASS', f'virtio-blk: disk=0 transport={transport}']
    missing = [marker for marker in markers if marker not in text]
    incomplete = [marker for marker in markers[:3] if text.count(marker) != 2]
    result = dict(volume=volume, firmware=firmware, transport=transport,
                  returncode=process.returncode, timed_out=timed_out, missing=missing,
                  incomplete=incomplete, log=log.name, seconds=round(time.monotonic() - started, 3),
                  passed=not timed_out and process.returncode == 1 and not missing and
                  not incomplete and not any(marker in text for marker in
                  ['PANIC:', 'PROFILE_PRIVACY_FAIL ', 'ABI_FAIL ', 'FAULT pid=']))
    if result['passed'] and volume == 'ext2':
        try:
            result['fsck'] = check_fs(disk, label)
            if dump(disk, '/seed.txt', label) != SEED:
                raise RuntimeError('host seed contents changed')
            result['seed_preserved'] = True
        except (OSError, RuntimeError) as error:
            result.update(passed=False, host_error=str(error))
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-3500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', choices=['ram', 'ext2', 'both'], default='both')
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results = []
    for volume in ['ram', 'ext2'] if args.volume == 'both' else [args.volume]:
        fixture(volume)
        for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
            for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
                result = run(volume, firmware, transport, args.timeout)
                results.append(result)
                (ROOT / 'build/profile-results.json').write_text(json.dumps(results, indent=2) + '\n')
                if not result['passed']:
                    raise SystemExit('Guest private saved-file contracts failed')


if __name__ == '__main__':
    main()

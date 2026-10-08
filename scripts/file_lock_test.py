"""Verify Linux file-lock lifetime on guest RAM and real ext2 filesystems."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from fetch import ROOT, LOCK
from ext2_test import create_volume, check_fs, dump, SEED
from file_lock_native import MARKERS, run as native


def fixture():
    subprocess.run(['make', 'build/axiom64.elf', 'build/init', 'build/file-lock-static',
                    'build/file-lock-dynamic', 'busybox'], cwd=ROOT, check=True)
    expected = json.loads((ROOT / 'sources.lock.json').read_text())['build_musl']['version']
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'musl-dev'], text=True)
    if version != expected:
        raise RuntimeError('fixture musl differs from the pinned build version')
    files = {name: (0o40755, b'') for name in ['bin', 'sbin', 'lib', 'etc', 'dev', 'proc',
                                             'sys', 'tmp', 'run', 'root']}
    for name, source in [('sbin/init', ROOT / 'build/init'),
                         ('bin/file-lock-static', ROOT / 'build/file-lock-static'),
                         ('bin/file-lock-dynamic', ROOT / 'build/file-lock-dynamic'),
                         ('lib/ld-musl-x86_64.so.1', Path('/lib/ld-musl-x86_64.so.1').resolve()),
                         ('bin/busybox', ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox'),
                         ('etc/net-test.sh', ROOT / 'userspace/tests/fs/file-lock.sh')]:
        files[name] = (0o100755, source.read_bytes())
    with (ROOT / 'build/rootfs-network.cpio').open('wb') as output:
        entries = [*sorted(files.items()), ('TRAILER!!!', (0, b''))]
        for inode, (name, (mode, data)) in enumerate(entries, 1):
            encoded = name.encode() + b'\0'
            values = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in values) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(data)
            output.write(bytes(-output.tell() % 4))
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'axiom64-file-lock.iso'], cwd=ROOT, check=True)


def run(firmware, transport, timeout, seed, scratch, reference):
    label = f'file-lock-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    disk = scratch / 'volume.raw'
    shutil.copyfile(seed, disk)
    seed_hash = hashlib.sha256(seed.read_bytes()).hexdigest()
    if hashlib.sha256(disk.read_bytes()).hexdigest() != seed_hash:
        raise RuntimeError('guest file-lock disk differs from the seed')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
               '-cdrom', str(ROOT / 'build/axiom64-file-lock.iso'), '-nic', 'none',
               '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,id=locks,format=raw,file={disk}',
               '-device', 'virtio-blk-pci,drive=locks,addr=5,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
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
    missing = [marker for marker in MARKERS if text.count(marker) != 4]
    if text.count('FILE_LOCK_UNSUPPORTED_PASS anonymous=3 mandatory=EINVAL opath=EBADF') != 4:
        missing.append('FILE_LOCK_UNSUPPORTED_PASS')
    missing += [f'FILE_LOCK_TESTS_PASS linkage={linkage}' for linkage in ['static', 'dynamic']
                if text.count(f'FILE_LOCK_TESTS_PASS linkage={linkage}') != 2]
    missing += [f'FILE_LOCK_READONLY_MOUNT_PASS linkage={linkage}' for linkage in ['static', 'dynamic']
                if text.count(f'FILE_LOCK_READONLY_MOUNT_PASS linkage={linkage}') != 1]
    missing += [marker for marker in ['FILE_LOCK_FILESYSTEM ramfs', 'FILE_LOCK_FILESYSTEM ext2',
                'FILE_LOCK_UNMOUNT_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
                if text.count(marker) != 1]
    traces = re.findall(r'FILE_LOCK_TRACE_PASS operations=4096 digest=([0-9a-f]{8})', text)
    error = None
    fsck = None
    try:
        if dump(disk, '/seed.txt', label) != SEED:
            raise RuntimeError('file-lock tests changed the independently created seed file')
        fsck = check_fs(disk, label)
    except Exception as failure:
        error = str(failure)
    passed = not timed_out and process.returncode == 1 and not missing and error is None and \
             len(traces) == 4 and set(traces) == {reference['trace']} and not any(
                 marker in text for marker in ['FILE_LOCK_FAIL', 'PANIC:', 'Page fault',
                                               'FILESYSTEM_SHUTDOWN_FAIL'])
    result = dict(firmware=firmware, transport=transport, returncode=process.returncode,
                  timed_out=timed_out, missing=missing, traces=traces, seed_sha256=seed_hash,
                  error=error, fsck=fsck, log=log.name, seconds=round(time.monotonic() - started, 3),
                  passed=passed)
    print(json.dumps(result), flush=True)
    if not passed:
        print(text[-2500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    reference = native()
    fixture()
    results = []
    with tempfile.TemporaryDirectory(prefix='axiom-file-lock-') as temporary:
        scratch = Path(temporary)
        seed = scratch / 'seed.raw'
        create_volume(seed)
        seed_hash = hashlib.sha256(seed.read_bytes()).hexdigest()
        for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
            for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
                result = run(firmware, transport, args.timeout, seed, scratch, reference)
                results.append(result)
                unchanged = hashlib.sha256(seed.read_bytes()).hexdigest() == seed_hash
                evidence = dict(native=reference, seed_sha256=seed_hash, seed_unchanged=unchanged,
                                boots=results)
                (ROOT / 'build/file-lock-results.json').write_text(json.dumps(evidence, indent=2) + '\n')
                if not unchanged or not result['passed']:
                    raise SystemExit('File-lock guest contract failed')


if __name__ == '__main__':
    main()

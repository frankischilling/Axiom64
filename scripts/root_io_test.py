#!/usr/bin/env python3
"""Mount a real ext2 root through a local backend with controlled flush latency."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from fetch import ROOT


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def run(image, seed, firmware, transport, delay, expect_timeout, timeout):
    prefix = f'root-io-{firmware}-{transport}-delay{delay}'
    log = ROOT / 'build' / (prefix + '.log')
    trace = ROOT / 'build' / (prefix + '.trace')
    trace.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix='axiom64-root-io-') as directory:
        scratch = Path(directory)
        disk, socket = scratch / 'root.raw', scratch / 'nbd.sock'
        shutil.copyfile(seed, disk)
        with (ROOT / 'build' / (prefix + '-backend.log')).open('w') as errors:
            backend = subprocess.Popen(['nbdkit', '-f', '--exit-with-parent', '-U', str(socket),
                'python', str(ROOT / 'scripts/delayed_block.py'), f'disk={disk}',
                f'delay={delay}', f'trace={trace}'], stdout=errors, stderr=errors)
        timed_out = selected = False
        deadline_at = None
        try:
            deadline = time.monotonic() + 5
            while not socket.exists():
                if backend.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('local NBD test backend did not start')
                time.sleep(.02)
            command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
                '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                '-nic', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                '-blockdev', f'driver=nbd,node-name=root,server.type=unix,server.path={socket}',
                '-device', 'virtio-blk-pci,drive=root,addr=5,rerror=report,werror=report,' +
                    ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
            if firmware == 'uefi':
                variables = scratch / 'OVMF_VARS.fd'
                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                            '-drive', f'if=pflash,format=raw,file={variables}']
            started = time.monotonic()
            with log.open('w') as output:
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                           stderr=subprocess.STDOUT)
                try:
                    while process.poll() is None:
                        text = log.read_text(errors='replace')
                        selected = 'VFS_ROOT_PASS filesystem=ext2' in text
                        if deadline_at is None and 'bytes=0 errno=110' in text:
                            deadline_at = time.monotonic()
                        if selected:
                            break
                        if time.monotonic() - started > timeout:
                            timed_out = True
                            break
                        time.sleep(.02)
                finally:
                    if process.poll() is None:
                        process.kill()
                    returncode = process.wait()
            text = log.read_text(errors='replace')
            selected |= 'VFS_ROOT_PASS filesystem=ext2' in text
            events = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
            deadline_seconds = deadline_at - events[0]['at'] if deadline_at and events else None
            if expect_timeout:
                passed = not selected and not timed_out and returncode == 3 and bool(events) and \
                    'BOOT_ROOT_FAIL stage=/dev/vda errno=5' in text and \
                    'virtio-blk: completion failed type=4 sector=0 bytes=0 errno=110' in text and \
                    deadline_seconds is not None and 25 <= deadline_seconds < 35
            else:
                passed = selected and not timed_out and 'BOOT_ROOT_FAIL' not in text and \
                    any(event['event'] == 'flush_end' and event['seconds'] >= delay for event in events)
            result = dict(firmware=firmware, transport=transport, flush_delay=delay,
                          expect_timeout=expect_timeout, passed=passed, timed_out=timed_out,
                          returncode=returncode, seconds=round(time.monotonic() - started, 2),
                          deadline_seconds=round(deadline_seconds, 2) if deadline_seconds else None,
                          events=events, log=log.name)
            print(json.dumps(result), flush=True)
            if not passed:
                print(text, flush=True)
            return result
        finally:
            backend.terminate()
            try:
                backend.wait(timeout=2)
            except subprocess.TimeoutExpired:
                backend.kill()
                backend.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, default=ROOT / 'build/axiom64-disk.iso')
    parser.add_argument('--disk', type=Path, default=ROOT / 'build/root-disk.raw')
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--delay', type=int, choices=range(41), default=3)
    parser.add_argument('--expect-timeout', action='store_true')
    parser.add_argument('--timeout', type=int, default=60)
    args = parser.parse_args()
    if args.expect_timeout and args.delay <= 30:
        parser.error('--expect-timeout needs a backend delay above the 30-second request deadline')
    before = digest(args.disk)
    results = [run(args.image.resolve(), args.disk.resolve(), firmware, transport, args.delay,
                   args.expect_timeout, args.timeout)
               for firmware in (['bios', 'uefi'] if args.firmware == 'both' else [args.firmware])
               for transport in (['modern', 'legacy'] if args.transport == 'both' else [args.transport])]
    unchanged = digest(args.disk) == before
    (ROOT / 'build' / f'root-io-delay{args.delay}-results.json').write_text(
        json.dumps(dict(seed_unchanged=unchanged, boots=results), indent=2) + '\n')
    passed = unchanged and all(result['passed'] for result in results)
    if passed:
        print(f'ROOT_IO_TESTS_PASS boots={len(results)}', flush=True)
    raise SystemExit(0 if passed else 1)

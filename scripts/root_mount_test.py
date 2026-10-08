#!/usr/bin/env python3
"""Probe root selection using a disposable QEMU disk snapshot, before userspace."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time
from fetch import ROOT


def probe(image, disk, firmware, transport, timeout, copy_disk=False):
    prefix = f'root-mount-{"copy-" if copy_disk else ""}{firmware}-{transport}'
    if copy_disk:
        copied = ROOT / 'build' / (prefix + '.raw')
        shutil.copyfile(disk, copied)
        disk = copied
    log = ROOT / 'build' / (prefix + '.log')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-vga', 'std', '-cdrom', str(image), '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-nic', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-drive', f'if=none,id=root,format=raw,cache=writeback,file={disk}',
               '-device', 'virtio-blk-pci,drive=root,addr=5,rerror=report,werror=report,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
    if not copy_disk:
        command.append('-snapshot')
    if firmware == 'uefi':
        variables = ROOT / 'build' / (prefix + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    timed_out = selected = False
    with log.open('w') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                text = log.read_text(errors='replace')
                if 'VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0' in text:
                    selected = True
                    break
                if time.monotonic() - started > timeout:
                    timed_out = True
                    break
                time.sleep(.05)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    text = log.read_text(errors='replace')
    selected |= 'VFS_ROOT_PASS filesystem=ext2 device=/dev/vda readonly=0' in text
    result = dict(firmware=firmware, transport=transport, backend='copy' if copy_disk else 'snapshot',
                  passed=selected and not timed_out and 'BOOT_ROOT_FAIL' not in text,
                  timed_out=timed_out, seconds=round(time.monotonic() - started, 2),
                  markers=[line for line in text.splitlines()
                           if 'VFS_ROOT_' in line or 'BOOT_ROOT_' in line], log=log.name)
    print(json.dumps(result), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--disk', type=Path, required=True)
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy'], default='modern')
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--copy-disk', action='store_true',
                        help='test a disposable copy with its actual host flush behavior')
    args = parser.parse_args()
    results = [probe(args.image.resolve(), args.disk.resolve(), firmware, args.transport,
                     args.timeout, args.copy_disk)
               for firmware in (['bios', 'uefi'] if args.firmware == 'both' else [args.firmware])]
    name = 'root-mount-copy-results.json' if args.copy_disk else 'root-mount-results.json'
    (ROOT / 'build' / name).write_text(json.dumps(results, indent=2) + '\n')
    raise SystemExit(0 if all(result['passed'] for result in results) else 1)

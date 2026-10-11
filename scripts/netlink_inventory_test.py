#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare compact Linux dumps and run the actual BusyBox interface commands."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from build_musl import loader
from fetch import LOCK, ROOT
from random_administration_test import checked_run, fingerprint, snapshot
from random_seed_test import image

COMMANDS = '''/bin/inventory
/bin/busybox ip link show
/bin/busybox ip link set eth0 up
/bin/busybox ip addr add 10.23.1.2/24 dev eth0
/bin/busybox ip route add default via 10.23.1.1
/bin/busybox ip addr show
/bin/busybox ip route show
/bin/inventory
/bin/busybox ip route del default via 10.23.1.1
/bin/busybox ip addr del 10.23.1.2/24 dev eth0
/bin/inventory
echo NETLINK_BUSYBOX_INVENTORY_PASS
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--linkage', choices=('native', 'static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/netlink-inventory-results')
    args = parser.parse_args()
    if args.linkage == 'native' and not args.native:
        parser.error('native linkage requires --native')
    if args.native and os.geteuid() != 0:
        parser.error('native fixtures require an isolated root network namespace')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    linkages = ('native', 'static', 'dynamic') if args.native and args.linkage == 'both' else (
        ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,))
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    *(f'build/{program}-{linkage}' for linkage in linkages for program in
                      (('netlink-inventory',) if args.native else
                       ('netlink-inventory', 'random', 'random-seed', 'random-seed-probe')))],
                   cwd=ROOT, check=True)
    inputs = snapshot(out)
    for name in ('userspace/tests/net/inventory.c', 'scripts/netlink_inventory_test.py',
                 'scripts/random_seed_test.py', 'scripts/image.py'):
        inputs[name] = fingerprint(ROOT / name)
    (out / 'source-inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    results = []
    for linkage in linkages:
        client = ROOT / f'build/netlink-inventory-{linkage}'
        if args.native:
            case = out / linkage
            case.mkdir()
            copied = case / 'inventory'
            shutil.copyfile(client, copied)
            script = case / 'namespace.sh'
            busybox = ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}/busybox"
            copied_busybox = case / 'busybox'
            shutil.copyfile(busybox, copied_busybox)
            script.write_text('set -eu\nbusybox=$1\nshift\nip link set lo up\n'
                              'ip link add eth0 type dummy\n' + COMMANDS.replace(
                                  '/bin/inventory', '"$@"').replace('/bin/busybox', '"$busybox"'))
            command = ['unshare', '--net', 'sh', str(script), str(copied_busybox)]
            if linkage == 'dynamic':
                command.append(str(loader()))
            command.append(str(copied))
            row, text = checked_run(command, case / 'native.log', 15)
            row.update(native=True, linkage=linkage, client=fingerprint(copied), busybox=fingerprint(copied_busybox))
            row['passed'] = row['returncode'] == 0 and not row['timed_out'] and text.count(
                'NETLINK_INVENTORY_PASS dumps=10 ') == 3 and 'NETLINK_BUSYBOX_INVENTORY_PASS\n' in text
            results.append(row)
        else:
            folder = out / (linkage + '-image')
            folder.mkdir()
            iso = image(folder, linkage, 'netlink-inventory', command=COMMANDS,
                        extra_products={'bin/inventory': client})
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for transport in ('modern', 'legacy') if args.transport == 'both' else (args.transport,):
                    case = out / f'{linkage}-{firmware}-{transport}'
                    case.mkdir()
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                               '-nic', 'none', '-netdev', 'user,id=net,net=10.23.1.0/24,host=10.23.1.1',
                               '-device', 'virtio-net-pci,netdev=net,' +
                               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on'),
                               '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                    if firmware == 'uefi':
                        variables = case / 'VARS.fd'
                        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                    row, text = checked_run(command, case / 'guest.log', 60)
                    row.update(native=False, linkage=linkage, firmware=firmware, transport=transport,
                               image=fingerprint(iso))
                    row['passed'] = row['returncode'] == 1 and not row['timed_out'] and text.count(
                        'NETLINK_INVENTORY_PASS dumps=10 ') == 3 and 'NETLINK_BUSYBOX_INVENTORY_PASS\n' in text
                    results.append(row)
                    (case / 'result.json').write_text(json.dumps(row, indent=2)+'\n')
                    if not row['passed']:
                        break
                if not results[-1]['passed']:
                    break
        (out / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
        print(json.dumps(results[-1]), flush=True)
        if not results[-1]['passed']:
            raise RuntimeError('the netlink inventory comparison failed')
    if not results or inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('the netlink inventory source changed')


if __name__ == '__main__':
    main()

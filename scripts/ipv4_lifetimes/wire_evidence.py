# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen original source, executable, runtime, boot image and lifetime wire captures."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

from disk_root import archive_entries
from ipv4_lifetimes.reader import decode, require
from ipv4_lifetimes.wire_packets import definitions
from ipv4_lifetimes.wire_trace import clocks, protocol
from ipv4_lifetimes.wire_worker import CLIENT, audit_image
from ipv4_source_route.artifacts import compilation, providers
from ipv4_source_route.native import configuration
from tcp6.inputs import digest

BOUND = ('wire_packets.py', 'wire_peer.py', 'wire_worker.py', 'wire_log.py', 'wire_trace.py', 'wire_evidence.py')


def json_lines(path):
    return [decode(line) for line in path.read_text().splitlines()]


def source(directory, expected):
    inputs = decode((directory / 'source/source-inputs.json').read_text())
    require(digest(directory / 'source/source.zip') == expected['source_zip_sha256'] and
            digest(directory / 'source/source-inputs.json') == expected['source_inputs_sha256'], 'exact retained source archive and inventory')
    with zipfile.ZipFile(directory / 'source/source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) == expected['files'] and set(archive.namelist()) == set(inputs),
                'complete unique public source members')
        for name, value in inputs.items():
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and '\\' not in name and
                    not set(path.parts) & {'.git', '.local', 'build', '__pycache__'} and
                    hashlib.sha256(archive.read(name)).hexdigest() == value, 'every exact retained public source byte')
    for name in BOUND:
        require(inputs['scripts/ipv4_lifetimes/' + name] == digest(Path(__file__).with_name(name)),
                'same original wire producers and independent readers')
    return inputs


def guest(directory, captured, original, shared):
    base = directory if shared is None else directory.parent / captured['profile']
    audit_image(base)
    products = decode((base / 'products.json').read_text())
    require(products['bin/ipv4-lifetime-wire'] == decode((directory / 'program.inputs.json').read_text())['product'] and
            archive_entries(base / 'root.cpio')['bin/ipv4-lifetime-wire'][1] == (directory / 'program').read_bytes(),
            'actual guest boot image contains the exact source-bound client')
    command = decode((directory / 'command.json').read_text())
    image = original / 'image.iso' if shared is None else shared / captured['profile'] / 'image.iso'
    expected = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-cdrom', str(image),
                '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
                '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if captured['firmware'] == 'uefi':
        firmware = original if shared is None else shared
        retained = directory if shared is None else directory.parent
        expected += ['-drive', 'if=pflash,format=raw,readonly=on,file=' + str(firmware / 'OVMF_CODE.fd'),
                     '-drive', 'if=pflash,format=raw,file=' + str(original / 'OVMF_VARS.fd')]
        require({name: dict(bytes=(retained / name).stat().st_size, sha256=digest(retained / name))
                 for name in ('OVMF_CODE.fd', 'OVMF_VARS.original.fd')} == captured['firmware_inputs'],
                'retained exact UEFI code and original variable store')
    virtio = 'virtio-net-pci,' + ('disable-legacy=on' if captured['transport'] == 'modern' else 'disable-modern=on')
    ports = []
    for lane, device in enumerate((virtio, 'e1000')):
        at = len(expected)
        require(len(command) >= at + 4 and command[at] == '-netdev' and command[at + 2] == '-device', 'two original QEMU socket adapters')
        prefix = f'socket,id=net{lane},connect=127.0.0.1:'
        require(command[at + 1].startswith(prefix), 'controlled loopback-only packet backend')
        port = command[at + 1][len(prefix):]
        require(port.isdigit() and str(int(port)) == port and 1024 <= int(port) <= 65535, 'actual bounded original socket port')
        ports.append(port)
        expected += ['-netdev', prefix + port, '-device', device + f',netdev=net{lane},mac=02:00:00:00:00:0{lane + 1}']
    require(command == expected and len(set(ports)) == 2, 'exact original QEMU process and immutable shared image')
    lines = (directory / 'client.log').read_text().replace('\r\n', '\n').splitlines()
    require([line for line in lines if line.startswith('Firmware: ')] == ['Firmware: ' + captured['firmware'].upper()] and
            [line for line in lines if line.startswith('NET_DEVICE ')] == [
                f'NET_DEVICE index={lane + 1} name=eth{lane} mtu=1500 carrier=1 mac=2:0:0:0:0:{lane + 1}' for lane in (0, 1)] and
            len([line for line in lines if line.startswith('virtio-net: index=1 transport=' + captured['transport'] + ' ')]) == 1 and
            lines.count('e1000: index=2 model=82540EM rx=64 tx=64') == 1 and lines.count('AXIOM64_TESTS_PASS') == 1 and
            lines.count('AXIOM64_EXIT status=0') == 1, 'actual guest firmware, both drivers and successful userspace exit')
    linkage = 'static ELF' if captured['profile'] == 'static' else 'dynamic musl'
    require(lines.count('exec pid=4 /bin/ipv4-lifetime-wire (' + linkage + ')') == 1, 'actual selected guest linkage')


def native(directory, captured, wire, ingress):
    profile = captured['profile']
    command = decode((directory / 'command.json').read_text())
    require(type(command) is list and len(command) == (4 if profile == 'dynamic' else 3) and
            command[-2:] == ['eth0', 'eth1'] and Path(command[-3]).is_absolute() and
            Path(command[-3]).name == 'ipv4-lifetime-wire-' + profile, 'actual selected isolated native client')
    runtime = decode((directory / 'runtime.json').read_text())
    maps = (directory / 'runtime-maps.txt').read_text()
    host = decode((directory / 'native.json').read_text())
    require(runtime['maps_sha256'] == digest(directory / 'runtime-maps.txt') and runtime['namespace'] == host['namespace'] and
            runtime['parent_namespace'] == host['parent_namespace'] and type(host['namespace']) is int and
            host['namespace'] != host['parent_namespace'] and runtime['executable'] == command[0],
            'actual mapped executable and independently isolated namespace')
    providers(directory, runtime, maps, profile, command[:-2], command[0] if profile == 'dynamic' else None)
    require(host['kernel_config_sha256'] == digest(directory / 'kernel.config') and configuration((directory / 'kernel.config').read_bytes()) > 0,
            'actual native kernel timer configuration')
    offloads = decode((directory / 'offloads.json').read_text())
    require(set(offloads) == {'eth0', 'peer0', 'eth1', 'peer1'}, 'both ends of both actual native devices')
    for value in offloads.values():
        require(set(value) == {'before', 'after'} and all(name + ': off' in value['after'] for name in
                ('tx-checksumming', 'tcp-segmentation-offload', 'generic-segmentation-offload', 'generic-receive-offload')),
                'complete native software transport checksums')
    statistics = decode((directory / 'packet-statistics.json').read_text())
    require(set(statistics) == {'peer0', 'peer1', 'client0', 'client1'}, 'all four independent native capture statistics')
    for role, rows in (('peer', wire), ('client', ingress)):
        for lane in (0, 1):
            value = statistics[role + str(lane)]
            require(set(value) == {'packets', 'drops'} and type(value['packets']) is int and type(value['drops']) is int and
                    value['drops'] == 0 and value['packets'] == sum(row['index'] == lane and row['direction'] != 'input' for row in rows) > 0,
                    'every actual packet retained with zero capture drops on every native tap')


def verify(directory):
    directory = Path(directory).resolve()
    captured = decode((directory / 'captured.json').read_text())
    require(captured['protocol_passed'] is True and captured['final_wire_acceptance'] is False and
            captured['mode'] in ('native', 'guest') and captured['profile'] in ('native', 'static', 'dynamic') and
            (captured['mode'] == 'native' or captured['profile'] != 'native') and
            captured['firmware'] in ('bios', 'uefi') and captured['transport'] in ('modern', 'legacy'), 'fixed original capture identity')
    original = PurePosixPath(captured['original_directory'])
    require(original.is_absolute() and '..' not in original.parts and str(original) == captured['original_directory'], 'canonical original capture directory')
    shared = PurePosixPath(captured['shared_directory']) if captured['shared_directory'] is not None else None
    require(shared is None or shared == original.parent, 'one original parent owns shared source and images')
    actual = {}
    for path in directory.rglob('*'):
        require(not path.is_symlink() and (path.is_file() or path.is_dir()), 'only retained ordinary artifact files and directories')
        if path.is_file() and path != directory / 'captured.json':
            actual[path.relative_to(directory).as_posix()] = digest(path)
    require(actual == captured['artifacts'] and digest(directory / 'client.log') == captured['client_log_sha256'] and
            digest(directory / 'command.json') == captured['command_sha256'], 'every exact original captured artifact byte')
    inputs = source(directory if shared is None else directory.parent, captured['source'])
    compilation(directory, inputs, captured['profile'], CLIENT)
    process = decode((directory / 'process.json').read_text())
    expected_status = 0 if captured['mode'] == 'native' else 1
    require(process['status'] == 'completed' and type(process['returncode']) is int and
            process['returncode'] == captured['returncode'] == expected_status and
            type(captured['elapsed_ns']) is int and captured['elapsed_ns'] >= 60_000_000_000, 'actual completed full-length workload')
    text = (directory / 'client.log').read_text()
    wire, ingress = json_lines(directory / 'wire.jsonl'), json_lines(directory / 'ingress.jsonl')
    events, commands = decode((directory / 'events.json').read_text()), decode((directory / 'commands.json').read_text())
    if captured['mode'] == 'native':
        native(directory, captured, wire, ingress)
    else:
        guest(directory, captured, original, shared)
    proof = protocol(text, wire, ingress, events, commands, captured['mode'] == 'native')
    clocks(text, wire, ingress, events, commands)
    require(captured['cases'] == [dict(case=number, transport=row['transport'], survival=row['survival'],
                retained_datagrams=int(row['retained']) if row['transport'] != 2 else 0, guard_tags=[1, 3])
                for number, row in enumerate(definitions())],
            'declared case summary matches the independently reopened packets')
    return dict(passed=True, mode=captured['mode'], profile=captured['profile'], firmware=captured['firmware'],
                transport=captured['transport'], observations=proof, full_matrix_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory)), flush=True)


if __name__ == '__main__':
    main()

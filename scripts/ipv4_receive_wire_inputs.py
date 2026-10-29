# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind packet observations to their retained sources, programs and boot images."""
import hashlib
import json
from pathlib import Path
import zipfile

from ipv4_receive_wire_records import require, unique
from tcp_fixture_inputs import audit_fixture
from ipv4_multicast_capture import cpio

CLIENTS = {'userspace/tests/net/ipv4_receive_wire.c', 'userspace/tests/net/ipv4_receive_wire_fixture.c',
           'userspace/tests/net/ipv4_receive_wire_fixture.h'}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4 * 1024 * 1024,
            'bounded original regular JSON input')
    return json.loads(path.read_text(), object_pairs_hook=unique)


def verify(directory, *, clients=CLIENTS, program_name='ipv4-receive-wire'):
    metadata = load(directory / 'results.json')
    native, profile = metadata['native'], metadata['profile']
    require(type(native) is bool and profile in ('native', 'static', 'dynamic') and
            (native or profile != 'native') and metadata['firmware'] in ('bios', 'uefi') and
            metadata['transport'] in ('modern', 'legacy') and metadata['error'] is None and
            metadata['returncode'] == (0 if native else 1) and metadata['source_unchanged'] is True,
            'actual successful process and supported profile identity')
    require(load(directory / 'process.json') == dict(status='completed', returncode=metadata['returncode']),
            'terminal original execution')
    source = metadata['source']
    require(digest(directory / 'source.zip') == source['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == source['source_inputs_sha256'], 'original source archive fingerprints')
    inputs = load(directory / 'source-inputs.json')
    require(len(inputs) == source['files'] and 1639 <= len(inputs) < 10000 and clients <= inputs.keys() and
            all(not Path(name).is_absolute() and '..' not in Path(name).parts and
                not set(Path(name).parts) & {'.git', '.local', 'build', 'downloads'} for name in inputs),
            'complete public corresponding source boundary')
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) and set(archive.namelist()) == set(inputs) and
                sum(item.file_size for item in archive.infolist()) <= 128 * 1024 * 1024,
                'unique bounded complete source archive')
        for name, fingerprint in inputs.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == fingerprint,
                    'source member fingerprint: ' + name)
    program = (directory / 'program.elf').read_bytes()
    require(program[:6] == b'\x7fELF\x02\x01', 'actual x86-64 ELF client')
    compiled = load(directory / 'program.inputs.json')
    require(compiled['product'] == dict(bytes=len(program), sha256=hashlib.sha256(program).hexdigest()) and
            set(compiled['sources']) == clients and
            all(inputs[name] == value for name, value in compiled['sources'].items()) and
            {name for name in compiled['command'] if name.endswith('.c')} == {name for name in clients if name.endswith('.c')},
            'actual compilation binds both C units and their shared header')
    products = {'program.elf', 'program.inputs.json'}
    if profile == 'dynamic':
        products.add('loader.elf')
    if native and profile == 'native':
        products |= {'host-libc.so.6', 'host-ld-linux-x86-64.so.2'}
    if not native:
        products |= {'kernel.elf', 'root.cpio', 'image.iso'}
    require(set(metadata['products']) == products and
            all(digest(directory / name) == value for name, value in metadata['products'].items()),
            'complete actual execution product fingerprints')
    command = load(directory / 'command.json')
    if native:
        require(len(command) == (2 if profile == 'dynamic' else 1) and Path(command[-1]).name == 'program.elf' and
                (profile != 'dynamic' or Path(command[0]).name == 'loader.elf'), 'exact retained native execution products')
        configuration = load(directory / 'native-configuration.json')
        cpu = configuration['packet_cpu']
        before = cpu['before']
        selected = cpu['selected']
        tasks = cpu['tasks']
        require(isinstance(before, list) and before and len(before) <= 4096 and
                all(type(value) is int and value >= 0 for value in before) and before == sorted(set(before)) and
                type(selected) is int and selected in before and cpu['actual'] == [selected] and
                cpu['network_namespace'] == configuration['namespace_inode'] and
                configuration['parent_namespace_inode'] > 0 and
                configuration['parent_namespace_inode'] != configuration['namespace_inode'] and
                cpu['policy'] == 'client-and-capture-on-one-cpu' and cpu['process'] > 0 and
                len(tasks) >= 3 and len({row['tid'] for row in tasks}) == len(tasks) and
                cpu['process'] in {row['tid'] for row in tasks} and
                all(row['tid'] > 0 and row['actual'] == [selected] for row in tasks) and
                cpu['client']['pid'] == metadata['native_client_pid'] and metadata['native_client_pid'] > 0 and
                cpu['client']['actual'] == [selected],
                'actual private client and every independent collector own one recorded allowed CPU')
        interfaces = configuration['interfaces']
        require([item['ifname'] for item in interfaces] == ['lo', 'eth0', 'eth1'] and
                all(item['address'] == f'52:54:00:12:34:1{lane}' and item['ifindex'] > 1
                    for lane, item in enumerate(interfaces[1:])) and configuration['namespace_inode'] > 0,
                'private two-TAP native namespace')
        expected = {f'/proc/sys/net/ipv4/conf/{name}/rp_filter': '0\n' for name in ('all', 'default', 'eth0', 'eth1')}
        expected.update({f'/proc/sys/net/ipv6/conf/eth{lane}/disable_ipv6': '1\n' for lane in range(2)})
        require(len(configuration['sysctls']) == 6 and
                {item['path']: item['configured'] for item in configuration['sysctls']} == expected and
                all(item.get('before') in ('0\n', '1\n', '2\n') for item in configuration['sysctls']) and
                all(item['ifname'] == 'lo' for item in configuration['initial_addresses']) and
                all(item['dev'] == 'lo' for item in configuration['initial_routes']),
                'recorded namespace-local weak-host input configuration')
        if program_name == 'ipv4-send-wire':
            links = configuration['stable_peer_links']
            require(links['kind'] == 'veth' and links['client_namespace_inode'] == configuration['namespace_inode'] and
                    links['peer_namespace_inode'] > 0 and links['peer_namespace_inode'] != configuration['namespace_inode'],
                    'actual independent native peer and client network namespaces')
            peer_interfaces = links['interfaces']
            require([row['ifname'] for row in peer_interfaces] == ['lo', 'peer0', 'peer1'] and
                    all(row['ifname'] == 'lo' for row in links['addresses']),
                    'stable native peer devices have no client IPv4 addresses')
            for lane, (client, peer) in enumerate(zip(interfaces[1:], peer_interfaces[1:])):
                require(client['link_index'] == peer['ifindex'] and peer['link_index'] == client['ifindex'] and
                        peer['address'] == f'02:41:58:52:58:0{lane}' and 'UP' in peer['flags'],
                        'actual paired Ethernet device indices, hardware and administrative state')
            require(len(links['features']) == 4 and
                    {(row['role'], row['device']) for row in links['features']} ==
                    {(role, name + str(lane)) for lane in range(2) for role, name in (('client', 'eth'), ('peer', 'peer'))} and
                    all(row['before'] and all(any(line.strip().startswith(field + ': off') for line in row['after'].splitlines())
                        for field in ('tx-checksumming', 'tcp-segmentation-offload', 'generic-segmentation-offload', 'generic-receive-offload'))
                        for row in links['features']), 'actual software checksum and segmentation configuration')
            require(len(links['peer_sysctls']) == 2 and
                    {row['path']: row['configured'] for row in links['peer_sysctls']} ==
                    {f'/proc/sys/net/ipv6/conf/peer{lane}/disable_ipv6': '1\n' for lane in range(2)} and
                    all(row['before'] in ('0\n', '1\n') for row in links['peer_sysctls']),
                    'actual private peer IPv6 configuration')
        require(metadata['native_kernel_release'], 'actual native kernel release')
    else:
        require(command[0] == 'qemu-system-x86_64' and command[command.index('-nic') + 1] == 'none' and
                Path(command[command.index('-cdrom') + 1]).name == 'image.iso', 'actual controlled guest boot command')
        devices = [command[at + 1] for at, token in enumerate(command[:-1]) if token == '-device']
        mode = ',disable-legacy=on' if metadata['transport'] == 'modern' else ',disable-modern=on'
        require(devices == ['isa-debug-exit,iobase=0xf4,iosize=0x04',
                'virtio-net-pci,netdev=peer0,addr=4,mac=52:54:00:12:34:10' + mode,
                'e1000,netdev=peer1,addr=5,mac=52:54:00:12:34:11'], 'actual paired devices and virtio transport')
        backends = [command[at + 1] for at, token in enumerate(command[:-1]) if token == '-netdev']
        require(len(backends) == 2 and all(value.startswith(f'socket,id=peer{lane},connect=127.0.0.1:') and
                value.rsplit(':', 1)[1].isdigit() and 0 < int(value.rsplit(':', 1)[1]) <= 65535
                for lane, value in enumerate(backends)) and len(set(backends)) == 2,
                'actual isolated paired socket backends')
        filters = [command[at + 1] for at, token in enumerate(command[:-1]) if token == '-object']
        require(len(filters) == 2 and all(value.startswith(f'filter-dump,id=capture{lane},netdev=peer{lane},file=') and
                Path(value.split('file=', 1)[1]).name == f'lane{lane}.pcap' for lane, value in enumerate(filters)),
                'independent original capture associated with each actual adapter')
        drives = [command[at + 1] for at, token in enumerate(command[:-1]) if token == '-drive']
        require((len(drives) == 2 and 'readonly=on' in drives[0] and 'OVMF_CODE_4M.fd' in drives[0] and
                drives[1].endswith('/OVMF_VARS.fd')) if metadata['firmware'] == 'uefi' else not drives,
                'actual requested guest firmware command')
        records = load(directory / 'products.json')
        members = cpio((directory / 'root.cpio').read_bytes())
        executables = {name: value['sha256'] for name, value in records.items() if name not in ('image.iso', 'kernel.elf', 'root.cpio')}
        require(set(executables) == {'sbin/init', 'bin/' + program_name, 'bin/busybox', 'lib/ld-musl-x86_64.so.1'} and
                executables['bin/' + program_name] == digest(directory / 'program.elf'), 'actual complete guest executable inventory')
        for name, value in records.items():
            data = (directory / name).read_bytes() if name in ('image.iso', 'kernel.elf', 'root.cpio') else members[name][1]
            require(value == dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()), 'actual guest product bytes')
        if profile == 'dynamic':
            require(executables['lib/ld-musl-x86_64.so.1'] == digest(directory / 'loader.elf'), 'actual dynamic runtime loader')
        audit_fixture(directory / 'image.iso', digest(directory / 'kernel.elf'), executables,
            ('#!/bin/sh\nset -e\n/bin/' + program_name + '\necho AXIOM64_TESTS_PASS\n').encode())
    return metadata, inputs

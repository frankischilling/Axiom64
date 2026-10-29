#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen raw UDP syscall, packet, source and actual boot-product evidence."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zipfile

from ipv4_multicast_capture import checksum, cpio, elf, require

RAW_SOURCE = 'userspace/tests/net/ipv4_raw_udp.c'
ABI_SOURCE = 'userspace/tests/net/ipv4_multicast_source.c'
MARKER = 'RAW_UDP_PASS operations=220 packets=23 quiet_windows=48 source_phases=7'
LOCAL, A, B, GROUP = 0x7f000001, 0x7f000002, 0x7f000003, 0xef7f2a71
RELEASES = {'6.6.87.2-microsoft-standard-WSL2', '6.17.0-1022-azure', '7.0.0-1017-azure'}
KERNELS = {'6.17.0-1022-azure': 'c8943d129291f60fa59728d1c82fa43300a292135384e9f2a192515e079622c4',
           '7.0.0-1017-azure': '824225c877a300b88b14d6ec09e0eee20dc88b16e3d390acfc1f464f696ef032'}
PHASES = [('initial-A', A, 21), ('initial-B', B, 38), ('retained-A', A, 5),
          ('after-final-A', A, 0), ('after-final-B', B, 38), ('new-unjoined-A', A, 0),
          ('new-joined-A', A, 5)]


def sha(body):
    return hashlib.sha256(body).hexdigest()


def rows(text):
    return [json.loads(line) for line in text.splitlines() if line.startswith('{')]


def operations(observed):
    return [(r['label'], r['returncode'], r['errno']) for r in observed if r.get('kind') == 'operation']


def udp(payload):
    return struct.pack('!HHHH', 41000, 39901, 8 + len(payload), 0) + payload


def packet_contract():
    small = udp(b'raw UDP actual full packet')
    invalid = bytearray(udp(b'bad UDP checksum remains raw data'))
    pseudo = struct.pack('!IIBBH', LOCAL, LOCAL, 0, 17, len(invalid))
    valid = checksum(pseudo + invalid) or 65535
    struct.pack_into('!H', invalid, 6, (valid ^ 1) or 2)
    maximum = udp(bytes((n * 13 + 7) & 255 for n in range(8, 65515)))
    expected = [('unicast-udp', False, LOCAL, LOCAL, small),
                *[('unicast-raw', True, LOCAL, LOCAL, small)] * 2,
                *[('zero-raw', True, LOCAL, LOCAL, b'')] * 2,
                *[('invalid-checksum-raw', True, LOCAL, LOCAL, bytes(invalid))] * 2,
                ('maximum-UDP-payload', False, LOCAL, LOCAL, maximum),
                *[('maximum-raw-packet', True, LOCAL, LOCAL, maximum)] * 2]
    for label, source, mask in PHASES:
        for receiver in range(6):
            if mask & (1 << receiver):
                expected.append((label + '-receiver' + str(receiver), receiver < 4, source, GROUP, udp(label.encode())))
    require(len(expected) == 23, 'raw UDP packet contract inventory')
    return expected


def check_log(text, reference, release, guest):
    observed = rows(text)
    identity = [r for r in observed if r.get('kind') == 'kernel']
    require(identity == [dict(kind='kernel', sysname='Axiom64' if guest else 'Linux', release=release)],
            'actual raw UDP execution domain and kernel')
    require(guest or release in RELEASES, 'measured native raw UDP kernel')
    require(text.splitlines().count(MARKER) == 1 and 'RAW_UDP_FAIL' not in text,
            'complete actual raw UDP client')
    require(len(operations(observed)) == 220 and operations(observed) == operations(reference),
            'complete native raw UDP operation and error order')
    require([r for r in observed if r.get('kind') in ('scalar', 'name')] ==
            [r for r in reference if r.get('kind') in ('scalar', 'name')],
            'actual raw UDP scalar and address results')
    sockets = [r for r in observed if r.get('kind') == 'socket']
    require(len(sockets) == 14 and all(r['returncode'] >= 0 and r['errno'] == 0 for r in sockets) and
            [(r['type'], r['protocol']) for r in sockets] == [(r['type'], r['protocol']) for r in reference if r.get('kind') == 'socket'],
            'actual raw UDP socket creation and protocol isolation')
    phases = [r for r in observed if r.get('kind') == 'phase']
    require([(r['label'], r['source'], r['expected_receivers']) for r in phases] == PHASES,
            'complete source membership and final-description phases')
    quiet = [r for r in observed if r.get('kind') == 'quiet']
    require(len(quiet) == 48 and [r['label'] for r in quiet] == [r['label'] for r in reference if r.get('kind') == 'quiet'],
            'complete independent raw UDP quiet observations')
    require(all(type(r['begin_ns']) is int and 0 <= r['begin_ns'] and r['end_ns'] - r['begin_ns'] >= 200000000 and
                r['revents'] == 0 for r in quiet), 'complete unscaled 200ms raw UDP quiet observation')
    packets = [r for r in observed if r.get('kind') == 'packet']
    expected = packet_contract()
    require(len(packets) == len(expected) and [r['label'] for r in packets] == [r[0] for r in expected],
            'complete actual raw UDP packet and source-filter inventory')
    for row, (label, raw, source, destination, datagram) in zip(packets, expected):
        body = bytes.fromhex(row['hex'])
        require(row['raw'] is raw and row['returncode'] == len(body) and row['errno'] == 0 and
                row['family'] == 2 and row['source'] == source and row['port'] == (0 if raw else 41000) and row['length'] == 16,
                'actual raw UDP receive result and source address')
        if raw:
            require(len(body) == 20 + len(datagram) and body[0] == 0x45 and body[9] == 17 and
                    int.from_bytes(body[2:4], 'big') == len(body) and not checksum(body[:20]) and
                    not int.from_bytes(body[6:8], 'big') & 0xbfff,
                    'actual complete raw UDP IPv4 header and checksum')
            require(body[1] == 0 and body[8] == (1 if destination == GROUP else 64) and
                    int.from_bytes(body[12:16], 'big') == source and int.from_bytes(body[16:20], 'big') == destination,
                    'actual raw UDP IP source destination and TTL')
            body = body[20:]
        require(body == (datagram if raw else datagram[8:]), 'actual complete raw UDP payload bytes')
    return dict(operations=220, packets=23, quiet_windows=48, source_phases=7)


def source(directory, metadata):
    archive = (directory / 'source.zip').read_bytes()
    encoded = (directory / 'source-inputs.json').read_bytes()
    require(sha(archive) == metadata['source']['source_zip_sha256'] and
            sha(encoded) == metadata['source']['source_inputs_sha256'], 'original complete raw UDP source fingerprints')
    inputs = json.loads(encoded)
    with zipfile.ZipFile(directory / 'source.zip') as bundle:
        require(len(bundle.namelist()) == metadata['source']['files'] == len(inputs) and set(bundle.namelist()) == set(inputs),
                'complete unique raw UDP source archive')
        for name, expected in inputs.items():
            require(not Path(name).is_absolute() and '..' not in Path(name).parts and sha(bundle.read(name)) == expected,
                    'actual raw UDP source archive bytes')
    return inputs


def compiled(directory, sources, name, source_name):
    binary = (directory / name).read_bytes()
    compiler = json.loads((directory / (name + '.inputs.json')).read_text())
    require(compiler['product'] == dict(bytes=len(binary), sha256=sha(binary)) and
            source_name in compiler['sources'] and all(sources.get(path) == value for path, value in compiler['sources'].items()),
            'actual raw UDP compilation and original source')
    elf(binary)
    return binary


def image(directory, metadata, program, original):
    archive = (directory / 'root.cpio').read_bytes()
    members = cpio(archive)
    if metadata['domain'].startswith('linux'):
        require(members['client'][1] == program and members['client'][0] & 0o111,
                'actual native raw UDP client inside initramfs')
        require(members['init'][0] & 0o111 and sha(members['init'][1]) == metadata['init_sha256'],
                'actual native raw UDP initialization program')
        elf(members['init'][1])
        kernel = (directory / 'native-kernel').read_bytes()
        require(sha(kernel) == KERNELS[metadata['release']] and kernel[0x202:0x206] == b'HdrS',
                'actual pinned native raw UDP kernel image')
        before = json.loads((directory / 'preexecution.json').read_text())
        require(sha(archive) == before['initramfs_sha256'] and sha(program) == before['program_sha256'] and
                sha(kernel) == before['kernel_sha256'], 'actual native raw UDP preexecution products')
        return
    require(members['bin/ipv4-raw-udp'][1] == program and members['bin/ipv4-raw-udp'][0] & 0o111,
            'actual raw UDP client inside guest initramfs')
    if original is not None:
        require(members['bin/ipv4-source-79'][1] == original and members['bin/ipv4-source-79'][0] & 0o111,
                'actual original multicast ABI client inside guest initramfs')
    script = b'#!/bin/sh\nset -e\n/bin/ipv4-raw-udp\n'
    if original is not None:script += b'/bin/ipv4-source-79\n'
    require(members['etc/net-test.sh'][1] == script + b'echo AXIOM64_TESTS_PASS\n', 'actual raw UDP guest boot script')
    for name in ('sbin/init', 'bin/busybox', 'lib/ld-musl-x86_64.so.1'):
        require(members[name][0] & 0o111, 'actual raw UDP guest loader and shell')
        elf(members[name][1])
    kernel = (directory / 'kernel.elf').read_bytes();elf(kernel)
    require(sha(kernel) == metadata['kernel_sha256'], 'actual raw UDP guest kernel fingerprint')
    with tempfile.TemporaryDirectory(prefix='axiom-raw-udp-reader-') as temporary:
        extracted = Path(temporary)
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(directory / 'image.iso'),
                        '-extract', '/boot/axiom64.elf', str(extracted / 'kernel'),
                        '-extract', '/boot/rootfs.cpio', str(extracted / 'root')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        require((extracted / 'kernel').read_bytes() == kernel and (extracted / 'root').read_bytes() == archive,
                'actual raw UDP ISO contains retained kernel and initramfs')
    recorded = json.loads((directory / 'products.json').read_text())
    for name, product in recorded.items():
        if name in ('image.iso', 'kernel.elf', 'root.cpio'):
            body = (directory / name).read_bytes()
        else:
            require(name in members, 'complete raw UDP retained runtime inventory')
            body = members[name][1]
        require(product == dict(bytes=len(body), sha256=sha(body)), 'actual raw UDP retained runtime product')



def verify(directory):
    directory = Path(directory)
    manifest = json.loads((directory / 'manifest.json').read_text())
    require(manifest['version'] == 1 and len(manifest['cases']) == 15, 'complete raw UDP comparison inventory')
    require(len({case['label'] for case in manifest['cases']}) == 15 and
            Counter((case['domain'],case['profile'],case['release'],case.get('firmware')) for case in manifest['cases']) ==
            Counter([*[(domain,profile,release,None) for domain,release in
                      [('host','6.6.87.2-microsoft-standard-WSL2'),('linux','6.17.0-1022-azure'),('linux','7.0.0-1017-azure')]
                      for profile in ('native','static','dynamic')],
                     *[('guest',profile,'0.1',firmware) for profile in ('static','dynamic') for firmware in ('bios','uefi')],
                     ('guest-control','static','0.1','bios'),('linux-control','native','6.17.0-1022-azure',None)]),
            'every raw UDP kernel linkage and firmware profile')
    require(set(manifest['products']) == {path.relative_to(directory).as_posix() for path in directory.rglob('*')
                                         if path.is_file() and path != directory / 'manifest.json'},
            'complete raw UDP retained product inventory')
    for name, expected in manifest['products'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and sha((directory / name).read_bytes()) == expected,
                'actual retained raw UDP product fingerprint')
    reference = rows((directory / 'reference.log').read_text())
    check_log((directory / 'reference.log').read_text(), reference, '6.6.87.2-microsoft-standard-WSL2', False)
    original_reference = [r for r in rows((directory / 'original79-reference.log').read_text()) if 'operation' in r]
    require(len(original_reference) == 79, 'complete original multicast ABI reference')
    outcomes = []
    client_sources, guest_kernels, programs = set(), set(), {}
    for metadata in manifest['cases']:
        name = metadata['label']
        require(Path(name).name == name, 'bounded raw UDP case directory')
        case = directory / name
        sources = source(case, metadata)
        program = compiled(case, sources, 'program.elf', RAW_SOURCE)
        client_sources.add(sources[RAW_SOURCE])
        programs.setdefault(metadata['profile'], set()).add(sha(program))
        if metadata['domain'] == 'guest':guest_kernels.add(metadata['kernel_sha256'])
        original = compiled(case, sources, 'original79.elf', ABI_SOURCE) if metadata['original79'] else None
        if metadata['domain'] != 'host':image(case, metadata, program, original)
        text = (case / 'client.log').read_text();observed = rows(text)
        if metadata['domain'] == 'guest-control':
            sockets = [r for r in observed if r.get('kind') == 'socket']
            require(sockets[-1]['type'] == 3 and sockets[-1]['protocol'] == 17 and sockets[-1]['returncode'] == -1 and
                    sockets[-1]['errno'] == 93 and metadata['returncode'] == 3 and
                    'RAW_UDP_FAIL operation=actual socket creation errno=93' in text and MARKER not in text and
                    'AXIOM64_TESTS_PASS' not in text, 'original unsupported raw UDP guest remains rejected')
        elif metadata['domain'] == 'linux-control':
            expected = operations(reference);position = next(n for n, r in enumerate(expected) if r[0] == 'raw-connect')
            require(operations(observed) == expected[:position] + [('raw-connect', -1, 101)] and
                    'RAW_UDP_FAIL operation=raw-connect errno=101' in text and MARKER not in text and
                    metadata['returncode'] == 35, 'original down-loopback native fixture remains rejected')
        else:
            guest = metadata['domain'] == 'guest'
            checked = check_log(text, reference, metadata['release'], guest)
            expected_exit = 1 if guest else 33 if metadata['domain'] == 'linux' else 0
            require(metadata['returncode'] == expected_exit, 'actual raw UDP execution exit')
            if guest:
                require(text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and 'AXIOM64_EXIT status=0' in text,
                        'complete actual raw UDP guest exit')
            if original is not None:
                abi_text = text if guest else (case / 'original79.log').read_text()
                require([r for r in rows(abi_text) if 'operation' in r] == original_reference and
                        abi_text.splitlines().count('IPV4 SOURCE FILTER ABI PASS cases=79') == 1,
                        'all original79 multicast ABI operations retained')
            outcomes.append(dict(label=name, domain=metadata['domain'], profile=metadata['profile'], **checked))
    require(len(client_sources) == 1, 'same actual raw UDP client source across comparisons')
    require(all(len(values) == 1 for values in programs.values()), 'same actual raw UDP executable for each linkage')
    require(guest_kernels == {manifest['guest_kernel_sha256']}, 'same actual raw UDP guest kernel across profiles')
    require(Counter(r['domain'] for r in outcomes) == {'host': 3, 'linux': 6, 'guest': 4},
            'all native and guest raw UDP comparison domains')
    return dict(passed=True, source_cases=15, positive_profiles=13, native_profiles=9, guest_profiles=4,
                original79_native_profiles=3, original79_guest_profiles=4, expected_old_failures=2,
                operations=2860, packets=299, complete_200ms_quiet_windows=624,
                source_filter_phases=91, native_packet_clock_acceptance=False,
                ethernet_wire_acceptance=False, full_feature_acceptance=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))

# SPDX-License-Identifier: GPL-3.0-or-later
"""Run finite address controls on both actual adapters in all eight guest profiles."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import time
import zipfile

from account_store_guest import fixture
from compile_uapi_client import audit_compile
from disk_root import archive_entries
from fetch import ROOT
from ipv4_lifetimes.reader import decode, require, verify as read
from tcp6.inputs import digest, freeze, write
from tcp_fixture_inputs import audit_fixture

CLIENT = 'userspace/tests/net/ipv4/address_lifetimes.c'
COMMAND = ('/bin/busybox ifconfig eth0 up\n/bin/busybox ifconfig eth1 up\n'
           '/bin/ipv4-address-lifetimes eth0 eth1')
SCRIPT = ('#!/bin/sh\nset -e\n' + COMMAND + '\necho AXIOM64_TESTS_PASS\n').encode()


def specifications():
    return [dict(linkage=linkage, firmware=firmware, transport=transport)
            for linkage in ('static', 'dynamic') for firmware in ('bios', 'uefi')
            for transport in ('modern', 'legacy')]


def name(spec):
    return '-'.join(spec[key] for key in ('linkage', 'firmware', 'transport'))


def boot_command(directory, spec, image):
    result = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
              '-cdrom', str(image), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
              '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    if spec['firmware'] == 'uefi':
        result += ['-drive', 'if=pflash,format=raw,readonly=on,file=' + str(directory.parent / 'OVMF_CODE.fd'),
                   '-drive', 'if=pflash,format=raw,file=' + str(directory / 'OVMF_VARS.fd')]
    virtio = 'virtio-net-pci,' + ('disable-legacy=on' if spec['transport'] == 'modern' else 'disable-modern=on')
    for index, device in enumerate((virtio, 'e1000')):
        result += ['-netdev', f'user,id=net{index},restrict=on', '-device',
                   device + f',netdev=net{index},mac=02:00:00:00:00:0{index + 1}']
    return result


def check_boot(text, spec):
    lines = text.replace('\r\n', '\n').splitlines()
    require(lines.count('Firmware: ' + spec['firmware'].upper()) == 1 and
            len([line for line in lines if line.startswith('Firmware: ')]) == 1,
            'actual selected guest firmware')
    require([line for line in lines if line.startswith('NET_DEVICE ')] == [
        f'NET_DEVICE index={index + 1} name=eth{index} mtu=1500 carrier=1 mac=2:0:0:0:0:{index + 1}'
        for index in (0, 1)] and
        len([line for line in lines if line.startswith('virtio-net: index=1 transport=' + spec['transport'] + ' ')]) == 1 and
        lines.count('e1000: index=2 model=82540EM rx=64 tx=64') == 1, 'actual guest adapters and PCI transport')
    require(lines.count('AXIOM64_TESTS_PASS') == 1 and lines.count('AXIOM64_EXIT status=0') == 1 and
            not any(marker in text for marker in ('PANIC:', 'FAULT pid=', 'IPV4_LIFETIME_FAIL')),
            'actual successful guest process exit without kernel or client failure')
    linkage = 'static ELF' if spec['linkage'] == 'static' else 'dynamic musl'
    require(lines.count('exec pid=4 /bin/ipv4-address-lifetimes (' + linkage + ')') == 1,
            'actual selected executable linkage')


def verify(directory):
    directory = Path(directory).resolve()
    index = decode((directory / 'completed.json').read_text())
    require(index['schema'] == 2 and type(index['schema']) is int and index['passed'] is True and
            index['profiles'] == specifications() and index['workers'] == 2,
            'complete fixed eight-profile guest control inventory')
    original = index['original_directory']
    require(type(original) is str, 'original guest output directory is recorded')
    original = PurePosixPath(original)
    require(original.is_absolute() and '..' not in original.parts and
            str(original) == index['original_directory'], 'canonical original guest output directory')
    source = index['source']
    inputs = decode((directory / 'source/source-inputs.json').read_text())
    require(digest(directory / 'source/source.zip') == source['source_zip_sha256'] and
            digest(directory / 'source/source-inputs.json') == source['source_inputs_sha256'],
            'exact complete retained source archive and inventory')
    with zipfile.ZipFile(directory / 'source/source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) == source['files'] and set(archive.namelist()) == set(inputs),
                'complete unique public source inventory')
        for filename, expected in inputs.items():
            require(hashlib.sha256(archive.read(filename)).hexdigest() == expected, 'every original retained source byte')
    for filename in ('reader.py', 'guest.py', 'controls.py', 'artifact_controls.py', 'protected.py'):
        require(inputs['scripts/ipv4_lifetimes/' + filename] == digest(Path(__file__).with_name(filename)),
                'same original guest producer and independent reader')
    for linkage in ('static', 'dynamic'):
        base = directory / linkage
        products = decode((base / 'products.json').read_text())
        for filename in ('image.iso', 'root.cpio', 'kernel.elf'):
            require(digest(base / filename) == products[filename]['sha256'] and
                    (base / filename).stat().st_size == products[filename]['bytes'], 'exact guest boot products')
        compiled = decode((base / 'program.inputs.json').read_text())
        require(compiled['sources'].get(CLIENT) == inputs[CLIENT] and
                all(inputs.get(filename) == expected for filename, expected in compiled['sources'].items()) and
                [filename for filename in compiled['command'] if filename.endswith('.c')] == [CLIENT] and
                ('-static' in compiled['command']) == (linkage == 'static') and
                compiled['product'] == products['bin/ipv4-address-lifetimes'],
                'exact source-bound client compilation and linkage')
        executables = {filename: value['sha256'] for filename, value in products.items()
                       if filename not in ('image.iso', 'root.cpio', 'kernel.elf')}
        audit_fixture(base / 'image.iso', products['kernel.elf']['sha256'], executables, SCRIPT,
                      products['root.cpio']['sha256'])
        program = archive_entries(base / 'root.cpio')['bin/ipv4-address-lifetimes'][1]
        require(program[:7] == b'\x7fELF\2\1\1' and struct.unpack_from('<H', program, 18)[0] == 62,
                'actual image contains an x86-64 ELF client')
        begin = struct.unpack_from('<Q', program, 32)[0]
        size, count = struct.unpack_from('<HH', program, 54)
        require(size == 56 and begin + count * size <= len(program), 'bounded actual program headers')
        interpreters = []
        for at in range(begin, begin + count * size, size):
            if struct.unpack_from('<I', program, at)[0] == 3:
                start, length = struct.unpack_from('<Q', program, at + 8)[0], struct.unpack_from('<Q', program, at + 32)[0]
                require(0 < length < 256 and start + length <= len(program), 'bounded actual ELF interpreter')
                interpreters.append(program[start:start + length])
        require(interpreters == ([] if linkage == 'static' else [b'/lib/ld-musl-x86_64.so.1\0']),
                'actual static or dynamic musl client in the boot image')
        require(products['kernel.elf']['sha256'] == index['kernel_sha256'], 'one common actual kernel')
    results = []
    for spec in specifications():
        case = directory / name(spec)
        receipt = decode((case / 'completed.json').read_text())
        require(receipt['profile'] == spec and receipt['returncode'] == 1 and not receipt['timed_out'] and
                receipt['log_sha256'] == digest(case / 'serial.log') and
                receipt['command_sha256'] == digest(case / 'command.json'), 'original successful guest execution')
        if spec['firmware'] == 'uefi':
            require(digest(directory / 'OVMF_CODE.fd') == index['firmware']['code'] and
                    digest(directory / 'OVMF_VARS.original.fd') == index['firmware']['variables'],
                    'exact retained UEFI firmware and original variable store')
        require(decode((case / 'command.json').read_text()) ==
                boot_command(original / name(spec), spec, original / spec['linkage'] / 'image.iso'),
                'exact actual guest process command and immutable image')
        text = (case / 'serial.log').read_text()
        check_boot(text, spec)
        proof = read(case / 'serial.log')
        require(receipt['observations'] == proof and type(receipt['elapsed_ns']) is int and
                receipt['elapsed_ns'] >= 18_000_000_000, 'full original real elapsed observations')
        results.append(dict(profile=spec, observations=proof))
    return dict(passed=True, profiles=8, adapters=2, requests=528, original_images_opened=True,
                results=results, native_wire_or_hosted_acceptance=False)


def produce(directory):
    directory = Path(directory).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'designated ignored output root')
    directory.mkdir(exist_ok=False)
    subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    'build/ipv4-address-lifetimes-static', 'build/ipv4-address-lifetimes-dynamic'], cwd=ROOT, check=True)
    (directory / 'source').mkdir()
    source = freeze(directory / 'source')
    inputs = decode((directory / 'source/source-inputs.json').read_text())
    firmware = {}
    for original, target, key in (('/usr/share/OVMF/OVMF_CODE_4M.fd', 'OVMF_CODE.fd', 'code'),
                                  ('/usr/share/OVMF/OVMF_VARS_4M.fd', 'OVMF_VARS.original.fd', 'variables')):
        shutil.copy2(original, directory / target)
        firmware[key] = digest(directory / target)
    for linkage in ('static', 'dynamic'):
        base = directory / linkage
        base.mkdir()
        program = ROOT / 'build' / ('ipv4-address-lifetimes-' + linkage)
        compiled = audit_compile(program, ROOT)
        write(base / 'program.inputs.json', compiled)

        def builder(provider, selected, destination):
            require(provider == 'build' and selected == linkage and destination == base, 'fixed prepared image inputs')
            return program, compiled

        fixture(base, 'build', linkage, program_builder=builder, filename='ipv4-address-lifetimes', command=COMMAND)

    def execute(spec):
        case = directory / name(spec)
        case.mkdir()
        if spec['firmware'] == 'uefi':
            shutil.copy2(directory / 'OVMF_VARS.original.fd', case / 'OVMF_VARS.fd')
        command = boot_command(case, spec, directory / spec['linkage'] / 'image.iso')
        write(case / 'command.json', command)
        began = time.monotonic_ns()
        timed_out = False
        with (case / 'serial.log').open('xb') as log:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            try:
                process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
        receipt = dict(profile=spec, returncode=process.returncode, timed_out=timed_out,
                       elapsed_ns=time.monotonic_ns() - began, log_sha256=digest(case / 'serial.log'),
                       command_sha256=digest(case / 'command.json'))
        write(case / 'process.json', receipt)
        require(process.returncode == 1 and not timed_out, 'terminal guest control process success')
        check_boot((case / 'serial.log').read_text(), spec)
        receipt['observations'] = read(case / 'serial.log')
        write(case / 'completed.json', receipt)
        print('IPV4_LIFETIME_GUEST_PASS ' + name(spec), flush=True)

    with ThreadPoolExecutor(max_workers=2) as workers:
        list(workers.map(execute, specifications()))
    require(all(digest(ROOT / filename) == expected for filename, expected in inputs.items()),
            'unchanged complete source throughout the guest matrix')
    write(directory / 'completed.json', dict(schema=2, passed=True, profiles=specifications(), workers=2,
          original_directory=str(directory),
          source=source, firmware=firmware, kernel_sha256=digest(ROOT / 'build/axiom64.elf')))
    proof = verify(directory)
    write(directory / 'verified.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--produce', action='store_true')
    args = parser.parse_args()
    print(json.dumps(produce(args.directory) if args.produce else verify(args.directory)), flush=True)


if __name__ == '__main__':
    main()

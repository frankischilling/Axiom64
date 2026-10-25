# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain and reopen the actual UDP clients, source inputs and boot images."""
import json
from pathlib import Path
import shutil

from build_musl import ensure
from compile_uapi_client import audit_compile
from fetch import ROOT, LOCK
from tcp_fixture_inputs import audit_fixture, digest, require

SOURCES = ('Makefile', 'dependencies.json', 'ports.lock.json', 'sources.lock.json',
           'boot/limine.conf', 'userspace/tests/net/udp.c', 'userspace/tests/net/udp.sh',
           'scripts/compile_uapi_client.py', 'scripts/linux_uapi.py', 'scripts/build_musl.py',
           'scripts/build_openssl.py', 'scripts/image.py', 'scripts/network_test.py',
           'scripts/network_fault.py', 'scripts/qmp.py', 'scripts/udp_test.py',
           'scripts/udp_peer.py', 'scripts/udp_matrix.py', 'scripts/udp_capture.py',
           'scripts/udp_inputs.py', 'scripts/tests/udp_capture_test.py',
           'scripts/tests/udp_capture_fixture_test.py', 'scripts/tests/fixtures/udp-wire/manifest.json')
PRODUCTS = ('image.iso', 'kernel.elf', 'client.elf', 'client.inputs.json', 'client.c',
            'net-test.sh', 'init', 'busybox', 'musl-manifest.json', 'musl-COPYRIGHT',
            'libc.a', 'compiler.specs')


def source_names(root):
    names = set(SOURCES)
    for prefix in ('kernel', 'userspace/init'):
        names.update(path.relative_to(root).as_posix() for path in (root / prefix).rglob('*')
                     if path.is_file() and path.suffix in ('.cpp', '.hpp', '.c', '.h', '.asm', '.ld'))
    return names


def record(directory, fault):
    """Snapshot one completed immutable image before running its four profiles."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    program = ROOT / 'build/udp-tests'
    compilation = audit_compile(program, ROOT)
    provider = ensure('build')
    files = {'image.iso': ROOT / 'build/udp-test.iso',
             'kernel.elf': ROOT / 'build/axiom64.elf', 'client.elf': program,
             'client.inputs.json': program.with_suffix('.inputs.json'),
             'client.c': ROOT / 'userspace/tests/net/udp.c',
             'net-test.sh': ROOT / 'userspace/tests/net/udp.sh',
             'init': ROOT / 'build/init',
             'busybox': ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}/busybox",
             'musl-manifest.json': provider / 'manifest.json',
             'musl-COPYRIGHT': provider / 'COPYRIGHT',
             'libc.a': provider / 'sysroot/usr/lib/libc.a',
             'compiler.specs': provider.parent / 'compiler.specs'}
    before = {name: digest(ROOT / name) for name in source_names(ROOT)}
    products = {}
    for name, original in files.items():
        fingerprint = digest(original)
        shutil.copyfile(original, directory / name)
        require(digest(directory / name) == fingerprint, 'complete copied UDP fixture product')
        products[name] = dict(bytes=original.stat().st_size, sha256=fingerprint)
    require(before == {name: digest(ROOT / name) for name in before},
            'UDP sources stay unchanged while recording the fixture')
    value = dict(version=1, fault=bool(fault), sources=before, products=products,
                 compilation=compilation, linkage='static',
                 guest_deadline_seconds=90, delayed_UEFI_fault_seconds=5)
    (directory / 'inputs.json').write_text(json.dumps(value, indent=2) + '\n')
    return value


def save_case(row, directory):
    directory = Path(directory)
    for name in (row['log'], row['log'][:-4] + '-gdb.log'):
        source = ROOT / 'build' / name
        if source.exists() and (name == row['log'] or row['fault']):
            shutil.copyfile(source, directory / name)
    (directory / 'result.json').write_text(json.dumps(row, indent=2) + '\n')


def audit(directory, input_root=ROOT, open_image=True):
    """Verify retained products and their corresponding project source snapshot."""
    directory, input_root = Path(directory), Path(input_root)
    value = json.loads((directory / 'inputs.json').read_text())
    require(value.get('version') == 1 and type(value.get('fault')) is bool and
            directory.name == ('fault' if value['fault'] else 'normal') and
            value.get('linkage') == 'static' and value.get('guest_deadline_seconds') == 90 and
            value.get('delayed_UEFI_fault_seconds') == 5, 'original complete UDP fixture contract')
    require(set(value['sources']) == source_names(input_root), 'complete UDP fixture source inventory')
    for name, fingerprint in value['sources'].items():
        require(digest(input_root / name) == fingerprint, 'actual UDP fixture source: ' + name)
    require(set(value['products']) == set(PRODUCTS), 'complete retained UDP product inventory')
    for name, product in value['products'].items():
        file = directory / name
        require(file.is_file() and not file.is_symlink() and file.stat().st_size == product['bytes'] and
                digest(file) == product['sha256'], 'actual retained UDP product: ' + name)
    compilation = json.loads((directory / 'client.inputs.json').read_text())
    require(compilation == value['compilation'] and
            compilation['product']['sha256'] == value['products']['client.elf']['sha256'] and
            '-static' in compilation['command'] and '-pthread' in compilation['command'] and
            compilation['command'][-2:] == ['-o', 'build/udp-tests'] and
            'userspace/tests/net/udp.c' in compilation['sources'],
            'actual original static UDP compile manifest and executable')
    locked = json.loads((input_root / 'ports.lock.json').read_text())['packages']
    package, = (entry for entry in locked if entry['name'] == 'linux-headers')
    require(compilation.get('uapi', {}).get('package') == package and
            '-isystem' in compilation['command'], 'pinned target Linux UAPI compilation inputs')
    for name, fingerprint in compilation['sources'].items():
        path = input_root / name
        require(path.resolve().is_relative_to(input_root.resolve()) and digest(path) == fingerprint,
                'actual original UDP compiler source: ' + name)
    require(value['products']['client.c']['sha256'] == value['sources']['userspace/tests/net/udp.c'] and
            value['products']['net-test.sh']['sha256'] == value['sources']['userspace/tests/net/udp.sh'],
            'retained UDP client and script match their corresponding sources')
    provider = json.loads((directory / 'musl-manifest.json').read_text())
    require(provider.get('provider') == 'build' and provider.get('target') == 'x86_64-linux-gnu' and
            provider['products']['sysroot/usr/lib/libc.a'] == value['products']['libc.a']['sha256'] and
            provider['products']['COPYRIGHT'] == value['products']['musl-COPYRIGHT']['sha256'],
            'actual UDP static libc and required notice match the retained provider')
    result = dict(passed=True, fault=value['fault'], actual_image_opened=False,
                  kernel_sha256=value['products']['kernel.elf']['sha256'],
                  client_sha256=value['products']['client.elf']['sha256'],
                  inputs_sha256=digest(directory / 'inputs.json'))
    if open_image:
        executables = {name: value['products'][product]['sha256'] for name, product in
                       (('sbin/init', 'init'), ('bin/busybox', 'busybox'), ('bin/udp-tests', 'client.elf'))}
        script = (b'export AXIOM64_UDP_FAULT=1\n' if value['fault'] else b'') + (directory / 'net-test.sh').read_bytes()
        result.update(audit_fixture(directory / 'image.iso', result['kernel_sha256'], executables, script))
    return result

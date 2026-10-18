# SPDX-License-Identifier: GPL-3.0-or-later
"""Record the real clients, loaders and fixture inputs used by ICMP acceptance."""
import hashlib
import json
from pathlib import Path
import subprocess
from fetch import ROOT, LOCK
from build_musl import ensure, loader

SOURCES = ('Makefile', 'scripts/tcp_capture_clock.py', 'scripts/tests/tcp_clock_mutations.py', 'userspace/tests/net/tcp_icmp.c', 'userspace/tests/net/tcp_icmp_cases.h',
           'scripts/tcp_icmp_peer.py', 'scripts/tcp_icmp_inputs.py', 'scripts/tcp_fault_test.py',
           'scripts/tcp_fault_native.py', 'kernel/net/tcp/icmp.cpp', 'kernel/include/net/tcp/icmp.hpp',
           'kernel/net/tcp/connection.cpp', 'kernel/include/net/tcp/connection.hpp',
           'kernel/net/tcp/socket.cpp', 'kernel/include/net/tcp/socket.hpp',
           'kernel/net/ipv4/core.cpp', 'kernel/net/ipv4/socket.cpp',
           'scripts/tests/tcp_icmp_error_order_test.py')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(linkage, native=False, image=None, label=None, program='tcp-icmp', sources=SOURCES):
    binary = ROOT / 'build' / f'{program}-{linkage}'
    products = [binary]
    providers = {}
    if linkage != 'native':
        for provider in ('build', 'runtime'):
            directory = ensure(provider)
            providers[provider] = json.loads((directory / 'manifest.json').read_text())
            products += [directory / 'manifest.json', directory / 'COPYRIGHT',
                         loader(provider), directory / 'sysroot/usr/lib/libc.a']
    if not native:
        products += [ROOT / 'build/axiom64.elf', ROOT / 'build/init', image,
                     ROOT / 'build' / f"busybox-{LOCK['busybox']['version']}" / 'busybox']
    host_libraries = {}
    if native and linkage == 'native':
        for name in ('libc.so.6', 'ld-linux-x86-64.so.2'):
            path = Path(subprocess.check_output(['gcc', '-print-file-name=' + name], text=True).strip()).resolve()
            if not path.is_file():
                raise ValueError(f'actual glibc library is missing: {name}')
            data = path.read_bytes()
            fingerprint = hashlib.sha256(data).hexdigest()
            retained = ROOT / 'build/tcp-host-libraries' / fingerprint / name
            retained.parent.mkdir(parents=True, exist_ok=True)
            if retained.exists():
                if digest(retained) != fingerprint:
                    raise ValueError(f'retained native shared library changed: {name}')
            else:
                retained.write_bytes(data)
            products.append(retained)
            host_libraries[name] = dict(path=str(path), sha256=fingerprint,
                                       retained=retained.relative_to(ROOT).as_posix())
    label = label or (f'{program}-linux-{linkage}' if native else f'{program}-{linkage}')
    value = dict(linkage=linkage, native=native,
                 compiler=subprocess.check_output(['gcc', '-dumpfullversion'], text=True).strip(),
                 sources={name: digest(ROOT / name) for name in sources},
                 products={path.relative_to(ROOT).as_posix(): digest(path) for path in products},
                 providers=providers, host_libraries=host_libraries)
    path = ROOT / 'build' / (label + '-inputs.json')
    path.write_text(json.dumps(value, indent=2) + '\n')
    return path.name

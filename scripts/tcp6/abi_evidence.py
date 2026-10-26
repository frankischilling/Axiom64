# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reopen the complete IPv6 TCP control comparison."""
import hashlib
import json
from pathlib import Path
import zipfile
from tcp6.inputs import digest
from tcp_fixture_inputs import audit_fixture


MARKER = 'TCP6_ABI_PASS address_cases=72 option_cases=10 name_cases=16 copy_cases=102'
WSL_KERNEL = '6.6.87.2-microsoft-standard-WSL2'
PRECHECK = ('TCP6_ABI_NATIVE_PRECHECK kernel=' + WSL_KERNEL +
            ' family=17 short_cases=6 errno=97')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def audit(directory):
    directory = Path(directory)
    report = json.loads((directory / 'results.json').read_text())
    rows = report['results']
    expected = {(profile, environment) for profile in ('static', 'dynamic')
                for environment in ('native', 'bios', 'uefi')}
    actual = [(row['profile'], row['environment']) for row in rows]
    require(len(actual) == len(set(actual)) == 6 and set(actual) == expected and
            report['complete'] is True and report['passed'] is True,
            'complete unique IPv6 TCP control matrix')
    source = report['source']
    require(digest(directory / 'source.zip') == source['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == source['source_inputs_sha256'],
            'IPv6 TCP control source fingerprints')
    sources = json.loads((directory / 'source-inputs.json').read_text())
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(archive.namelist()) == len(sources) == source['files'] and
                set(archive.namelist()) == set(sources), 'complete IPv6 TCP control source archive')
        for name, fingerprint in sources.items():
            require(hashlib.sha256(archive.read(name)).hexdigest() == fingerprint,
                    'actual IPv6 TCP control source bytes')
    kernels = set()
    for profile in ('static', 'dynamic'):
        case = directory / profile
        compiled = json.loads((case / 'program.inputs.json').read_text())
        program = digest(case / 'program')
        require(compiled['product']['sha256'] == program and
                compiled['sources']['userspace/tests/net/tcp6/abi.c'] == sources['userspace/tests/net/tcp6/abi.c'],
                'compiled IPv6 TCP control program identity')
        require(all(not name.startswith('/') and name in sources and sources[name] == fingerprint
                    for name, fingerprint in compiled['sources'].items()),
                'all compiled IPv6 TCP control source bindings')
        image = json.loads((case / 'image-audit.json').read_text())
        kernel = digest(case / 'kernel.elf')
        kernels.add(kernel)
        require(image['kernel_sha256'] == kernel and image['products']['bin/tcp6-abi'] == program,
                'actual IPv6 TCP control image products')
        audit_fixture(case / 'image.iso', kernel, image['products'], image['script'].encode())
        for environment in ('native', 'bios', 'uefi'):
            row = next(item for item in rows if item['profile'] == profile and item['environment'] == environment)
            log = case / ('native.log' if environment == 'native' else environment + '.log')
            text = log.read_text()
            require(row['passed'] is True and row['returncode'] == (0 if environment == 'native' else 1) and
                    row['program_sha256'] == program and row['log_sha256'] == digest(log),
                    'actual IPv6 TCP control execution identity')
            require(text.splitlines().count(MARKER) == 1 and
                    not any(failure in text for failure in ('TCP6_ABI_FAIL', 'PANIC:', 'FAULT pid=')),
                    'all IPv6 TCP control application observations')
            before = json.loads((case / (environment + '-before.json')).read_text())
            observed = [line for line in text.splitlines() if line.startswith('TCP6_ABI_NATIVE_PRECHECK')]
            expected_precheck = [PRECHECK] if environment == 'native' and before['kernel'] == WSL_KERNEL else []
            require(observed == expected_precheck, 'exact native-only packet-family prevalidation profile')
            require(before['source'] == source and before['program_sha256'] == program,
                    'preexecution IPv6 TCP control source and program')
            command = before['command']
            if environment == 'native':
                require(len(command) == (2 if profile == 'dynamic' else 1) and
                        Path(command[-1]).name == 'program' and
                        (profile != 'dynamic' or Path(command[0]).name == 'loader'),
                        'actual native IPv6 TCP control invocation')
                require(before['deadline_seconds'] == 60 and bool(before['kernel']),
                        'native IPv6 TCP control deadline and kernel')
                if profile == 'dynamic':
                    require(before['loader_sha256'] == digest(case / 'loader') ==
                            image['products']['lib/ld-musl-x86_64.so.1'],
                            'same actual native and guest musl loader')
            else:
                require(command[0] == 'qemu-system-x86_64' and '-cdrom' in command and
                        Path(command[command.index('-cdrom')+1]).name == 'image.iso' and
                        all(command[command.index(flag)+1] == value for flag, value in
                            (('-machine', 'pc'), ('-cpu', 'max'), ('-m', '256M'), ('-nic', 'none'),
                             ('-display', 'none'), ('-serial', 'stdio'), ('-monitor', 'none'))) and
                        '-no-reboot' in command and
                        'isa-debug-exit,iobase=0xf4,iosize=0x04' in command,
                        'actual guest IPv6 TCP control invocation')
                require(before['deadline_seconds'] == 90 and before['kernel_sha256'] == row['kernel_sha256'] == kernel and
                        before['image_sha256'] == row['image_sha256'] == digest(case / 'image.iso'),
                        'original guest IPv6 TCP control deadline and image')
                require(text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                        'Firmware: ' + environment.upper() in text and 'AXIOM64_EXIT status=0' in text,
                        'actual IPv6 TCP control guest completion')
    require(len(kernels) == 1, 'one actual IPv6 TCP control kernel')
    return dict(passed=True, profiles=6, native=2, guests=4, cases_each=200,
                actual_images=2, complete_source_files=len(sources), kernel_sha256=kernels.pop())

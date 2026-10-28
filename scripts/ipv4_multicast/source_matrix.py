# SPDX-License-Identifier: GPL-3.0-or-later
"""Run and independently reopen all six source-filter cases and 66 profiles."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import zipfile

from fetch import LOCK, ROOT
from build_musl import loader
from ipv4_multicast.source_capture import verify as verify_case
from ipv4_multicast_capture import cpio, require
from tcp6.inputs import digest, freeze

SCENARIOS = ('delivery', 'settled', 'queries', 'mtu', 'overlap', 'query-bounds')
CLIENT = ('userspace/tests/net/ipv4_multicast_source_wire.c',
          'userspace/tests/net/ipv4_multicast_source_delivery.c',
          'userspace/tests/net/ipv4_multicast_source_delivery.h')


def specifications():
    result = []
    for scenario in SCENARIOS:
        for profile in ('native', 'static', 'dynamic'):
            label = scenario + '-linux-' + profile
            result.append(dict(label=label, path=label, scenario=scenario, native=True, profile=profile,
                               firmware='bios', transport='modern'))
        for profile in ('static', 'dynamic'):
            for firmware in ('bios', 'uefi'):
                for transport in ('modern', 'legacy'):
                    label = '-'.join((scenario, 'guest', profile, firmware, transport))
                    result.append(dict(label=label, path=label, scenario=scenario, native=False,
                                       profile=profile, firmware=firmware, transport=transport))
    return result


def snapshot(directory, source):
    require(digest(directory / 'source.zip') == source['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == source['source_inputs_sha256'],
            'source matrix original complete source fingerprints')
    inputs = json.loads((directory / 'source-inputs.json').read_text())
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(inputs) == source['files'] == len(archive.namelist()) and set(inputs) == set(archive.namelist()),
                'source matrix complete unique source archive')
        for name, expected in inputs.items():
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and
                    hashlib.sha256(archive.read(name)).hexdigest() == expected,
                    'source matrix actual original source bytes')
    return inputs


def admission(case, specification, cohort):
    metadata = json.loads((case / 'results.json').read_text())
    require(metadata['source_case'] == specification['scenario'] and metadata['suite'] == 'source' and
            metadata['native'] == specification['native'] and metadata['profile'] == specification['profile'] and
            metadata['firmware'] == specification['firmware'] and metadata['transport'] == specification['transport'],
            'source matrix exact workload domain linkage firmware and transport')
    result = verify_case(case)
    inputs = json.loads((case / 'source-inputs.json').read_text())
    require(all(inputs.get(name) == cohort['client'][name] for name in CLIENT) and
            {name: value for name, value in inputs.items() if name.startswith('kernel/')} == cohort['kernel_sources'],
            'source matrix common actual client and kernel source')
    program = case / ('ipv4-multicast-source-wire-' + specification['profile'])
    require(digest(program) == cohort['programs'][specification['profile']],
            'source matrix byte-identical executable for each linkage')
    if specification['profile'] == 'dynamic':
        for provider in ('build', 'runtime'):
            name = 'musl-' + provider + '-loader'
            require(digest(case / name) == cohort['runtime'][name],
                    'source matrix same actual musl runtime products')
    if specification['profile'] == 'native':
        for name in ('host-libc.so.6', 'host-ld-linux-x86-64.so.2'):
            require(digest(case / name) == cohort['runtime'][name],
                    'source matrix same actual host runtime products')
    if not specification['native']:
        require(result['actual_kernel_sha256'] == cohort['kernel_sha256'],
                'source matrix same actual current guest kernel')
        members = cpio((case / 'rootfs-network.cpio').read_bytes())
        require(digest(case / 'init') == cohort['runtime']['init'] and
                hashlib.sha256(members['bin/busybox'][1]).hexdigest() == cohort['runtime']['busybox'],
                'source matrix same actual guest init and shell')
    else:
        rows = [json.loads(line) for line in (case / 'client.log').read_text().splitlines() if line.startswith('{')]
        require(rows[0]['release'] == metadata['native_kernel_release'],
                'source matrix actual native kernel identity')
    return result


def verify(directory, domain='all'):
    directory = Path(directory)
    index = json.loads((directory / 'source-matrix.json').read_text())
    require(domain in ('all', 'guest'), 'explicit source matrix verification domain')
    require(index['version'] == 1 and index['complete'] is True and index['cases'] == specifications(),
            'source matrix complete fixed 66-profile inventory')
    inputs = snapshot(directory, index['source'])
    require(digest(directory / 'kernel.elf') == index['kernel_sha256'] and
            set(index['programs']) == {'native', 'static', 'dynamic'} and
            set(index['runtime']) == {'init', 'busybox', 'musl-build-loader', 'musl-runtime-loader',
                                      'host-libc.so.6', 'host-ld-linux-x86-64.so.2'} and
            all(digest(directory / 'runtime' / name) == value for name, value in index['runtime'].items()) and
            all(digest(directory / 'programs' / (name + '.elf')) == value for name, value in index['programs'].items()),
            'source matrix original preexecution kernel programs and runtimes')
    require(index['client'] == {name: inputs[name] for name in CLIENT} and
            index['kernel_sources'] == {name: value for name, value in inputs.items() if name.startswith('kernel/')} and
            set(index['programs']) == {'native', 'static', 'dynamic'},
            'source matrix full cohort source and linkage binding')
    results = []
    for specification in index['cases']:
        if domain == 'guest' and specification['native']:
            continue
        name = specification['path']
        require(name == specification['label'] and Path(name).name == name and
                (directory / name).is_dir() and not (directory / name).is_symlink(),
                'source matrix bounded actual profile directory')
        results.append(dict(label=name, **admission(directory / name, specification, index)))
    require(Counter((row['scenario'], row['native']) for row in results) ==
            Counter({(scenario, native): 3 if native else 8 for scenario in SCENARIOS for native in (True, False) if domain == 'all' or not native}),
            'source matrix every native and guest scenario')
    reporting = [row for row in results if row['scenario'] != 'delivery']
    delivery = [row for row in results if row['scenario'] == 'delivery']
    report_lanes = [lane for row in reporting for lane in row['lanes']]
    delivery_lanes = [lane for row in delivery for lane in row['lanes']]
    return dict(passed=True, domain=domain, profiles=len(results), native_profiles=18 if domain == 'all' else 0, guest_profiles=48,
                source_files=len(inputs), actual_kernel_sha256=index['kernel_sha256'],
                reports=sum(row['reports'] for row in report_lanes),
                queries=sum(row['queries'] for row in report_lanes),
                report_full_three_second_windows=sum(row['complete_three_second_observations'] for row in report_lanes),
                first_packet_barriers=sum(row['first_packet_barriers'] for row in report_lanes),
                delivery_sends=sum(row['actual_sends'] for row in delivery),
                delivery_receives=sum(row['actual_receives'] for row in delivery),
                delivery_full_200ms_quiet_windows=sum(row['complete_200ms_quiet_windows'] for row in delivery),
                delivery_full_three_second_windows=sum(row['complete_three_second_wire_windows'] for row in delivery),
                delivery_injected_packets=sum(row['injected'] for row in delivery_lanes),
                delivery_wire_output_packets=sum(row['output'] for row in delivery_lanes),
                results=results, full_native_guest_acceptance=domain == 'all', full_feature_acceptance=False)


def produce(directory, reused_cases=None, progress=None):
    directory = Path(directory).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'source matrix output must be below build')
    subprocess.run(['make', '-j3', *['build/ipv4-multicast-source-wire-' + profile for profile in ('native', 'static', 'dynamic')]], cwd=ROOT, check=True)
    directory.mkdir(parents=True, exist_ok=False)
    frozen = freeze(directory)
    inputs = json.loads((directory / 'source-inputs.json').read_text())
    runtime = {'init': ROOT / 'build/init',
               'busybox': ROOT / ('build/busybox-' + LOCK['busybox']['version']) / 'busybox',
               **{'musl-' + provider + '-loader': loader(provider) for provider in ('build', 'runtime')}}
    for name in ('libc.so.6', 'ld-linux-x86-64.so.2'):
        runtime['host-' + name] = Path(subprocess.check_output(['gcc', '-print-file-name=' + name], text=True).strip()).resolve()
    (directory / 'runtime').mkdir()
    (directory / 'programs').mkdir()
    for name, path in runtime.items():
        shutil.copy2(path, directory / 'runtime' / name)
    for profile in ('native', 'static', 'dynamic'):
        shutil.copy2(ROOT / ('build/ipv4-multicast-source-wire-' + profile), directory / 'programs' / (profile + '.elf'))
    shutil.copy2(ROOT / 'build/axiom64.elf', directory / 'kernel.elf')
    index = dict(version=1, complete=False, source=frozen, cases=specifications(),
                 client={name: inputs[name] for name in CLIENT},
                 kernel_sources={name: value for name, value in inputs.items() if name.startswith('kernel/')},
                 kernel_sha256=digest(ROOT / 'build/axiom64.elf'),
                 runtime={name: digest(directory / 'runtime' / name) for name in runtime},
                 programs={profile: digest(ROOT / ('build/ipv4-multicast-source-wire-' + profile))
                           for profile in ('native', 'static', 'dynamic')}, results=[])
    def save():
        temporary = directory / 'source-matrix.tmp'
        temporary.write_text(json.dumps(index, indent=2) + '\n')
        os.replace(temporary, directory / 'source-matrix.json')
    save()
    for specification in index['cases']:
        label = specification['label']
        case = directory / label
        reused = label in (reused_cases or {})
        if reused:
            original = Path(reused_cases[label])
            admission(original, specification, index)
            shutil.copytree(original, case, copy_function=os.link)
            returncode = 0
        else:
            command = [sys.executable, '-B', str(ROOT / 'scripts/ipv4_multicast_test.py'), '--suite', 'source',
                       '--source-case', specification['scenario'], '--profile', specification['profile'],
                       '--firmware', specification['firmware'], '--transport', specification['transport'],
                       '--directory', str(case)]
            if specification['native']:
                command.append('--native')
            with (directory / (label + '.producer.log')).open('xb') as log:
                returncode = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT).returncode
        require(digest(ROOT / 'build/axiom64.elf') == index['kernel_sha256'] and
                all(digest(ROOT / name) == value for name, value in inputs.items()),
                'source matrix source and kernel unchanged throughout producers')
        try:
            checked = admission(case, specification, index)
        except (ValueError, AssertionError, OSError, KeyError, IndexError) as failure:
            accepted, reason = False, type(failure).__name__ + ': ' + str(failure)
        else:
            accepted, reason = returncode == 0, None
        index['results'].append(dict(label=label, producer_returncode=returncode, reused=reused,
                                     independent_accepted=accepted, rejection=reason))
        save()
        print(json.dumps(index['results'][-1]), flush=True)
        if progress is not None:
            progress(index, case)
    index['complete'] = True
    save()
    if all(row['independent_accepted'] for row in index['results']):
        result = verify(directory)
        (directory / 'independent-audit.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    return dict(passed=False, profiles_attempted=len(index['results']), results=index['results'],
                original_failures_retained=True, full_feature_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--produce', action='store_true')
    parser.add_argument('--domain', choices=('all', 'guest'), default='all')
    args = parser.parse_args()
    if args.produce and args.domain != 'all':
        parser.error('production always requires every native and guest profile')
    result = produce(args.directory) if args.produce else verify(args.directory, domain=args.domain)
    print(json.dumps(result, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

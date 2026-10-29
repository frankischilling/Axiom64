#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject incomplete cohorts and consistently changed source/runtime products."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from ipv4_multicast.source_controls import copy_input
from ipv4_multicast.source_capture import verify as verify_case
from ipv4_multicast.source_matrix import verify


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def changed_runtime(candidate, case_name, program, save):
    case = candidate / case_name
    metadata = json.loads((case / 'results.json').read_text())
    inputs = json.loads((case / 'inputs.json').read_text())
    name = 'ipv4-multicast-source-wire-static' if program else 'musl-runtime-loader'
    original = (case / name).read_bytes()
    changed = bytearray(original)
    changed[9] ^= 1
    save(case_name + '/' + name, bytes(changed))
    original_archive = (case / 'rootfs-network.cpio').read_bytes()
    archive = bytearray(original_archive)
    offset = archive.find(original)
    assert offset >= 0
    archive[offset + 9] ^= 1
    save(case_name + '/rootfs-network.cpio', bytes(archive))
    # Both changes preserve length. Replace the actual embedded CPIO bytes
    # directly, retaining every original ISO and boot-layout byte outside it.
    image = bytearray((case / 'guest.iso').read_bytes())
    location = image.find(original_archive)
    assert location >= 0 and image.find(original_archive, location + 1) == -1
    image[location:location + len(original_archive)] = archive
    save(case_name + '/guest.iso', bytes(image))
    names = [name, 'rootfs-network.cpio', 'guest.iso']
    if program:
        compiler_name = name + '.inputs.json'
        compiler = json.loads((case / compiler_name).read_text())
        compiler['product']['sha256'] = digest(case / name)
        save(case_name + '/' + compiler_name, encoded(compiler))
        names.append(compiler_name)
    for name in names:
        metadata['products'][name] = inputs['products'][name] = digest(case / name)
    save(case_name + '/results.json', encoded(metadata))
    save(case_name + '/inputs.json', encoded(inputs))


def changed_source(candidate, case_name, save):
    case = candidate / case_name
    metadata = json.loads((case / 'results.json').read_text())
    inputs = json.loads((case / 'inputs.json').read_text())
    sources = json.loads((case / 'source-inputs.json').read_text())
    name = 'kernel/net/tcp/socket.cpp'
    with zipfile.ZipFile(case / 'source.zip') as archive:
        bodies = {entry: archive.read(entry) for entry in archive.namelist()}
    bodies[name] += b'\n// Changed source context control.\n'
    sources[name] = hashlib.sha256(bodies[name]).hexdigest()
    temporary = candidate / 'changed-source.zip'
    with zipfile.ZipFile(temporary, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, body in bodies.items():archive.writestr(name, body)
    save(case_name + '/source.zip', temporary.read_bytes())
    temporary.unlink()
    save(case_name + '/source-inputs.json', encoded(sources))
    source = dict(inputs['source'], source_zip_sha256=digest(case / 'source.zip'),
                  source_inputs_sha256=digest(case / 'source-inputs.json'))
    metadata['source'] = inputs['source'] = source
    save(case_name + '/results.json', encoded(metadata))
    save(case_name + '/inputs.json', encoded(inputs))


def run(directory, output, domain='all'):
    directory, output = Path(directory).resolve(), Path(output).resolve()
    if not all(path.is_relative_to((ROOT / 'build').resolve()) for path in (directory, output)) or output.is_relative_to(directory) or directory.is_relative_to(output):
        raise ValueError('matrix controls require separate owned build directories')
    positive = verify(directory, domain=domain)
    output.mkdir(parents=True, exist_ok=False)
    original = {str(path.relative_to(directory)): digest(path) for path in directory.rglob('*') if path.is_file()}
    results = []
    for mutation in ('missing-profile', 'repeated-profile', 'missing-scenario', 'kernel', 'client',
                     'same-linkage-executable', 'matching-runtime-loader', 'kernel-source-context'):
        candidate = output / mutation
        shutil.copytree(directory, candidate, copy_function=copy_input)
        changed = {}
        def save(name, body):
            path = candidate / name
            if path.exists():path.unlink()
            path.write_bytes(body)
            changed[name] = body
        index = json.loads((candidate / 'source-matrix.json').read_text())
        individual = None
        if mutation == 'missing-profile':index['cases'].pop()
        elif mutation == 'repeated-profile':index['cases'][-1] = index['cases'][0]
        elif mutation == 'missing-scenario':index['cases'] = [case for case in index['cases'] if case['scenario'] != 'queries']
        elif mutation == 'kernel':index['kernel_sha256'] = '0' * 64
        elif mutation == 'client':index['client']['userspace/tests/net/ipv4_multicast_source_delivery.c'] = '0' * 64
        else:
            case_name = 'delivery-guest-dynamic-uefi-legacy' if mutation == 'matching-runtime-loader' else 'delivery-guest-static-bios-modern'
            if mutation == 'kernel-source-context':changed_source(candidate, case_name, save)
            else:changed_runtime(candidate, case_name, mutation == 'same-linkage-executable', save)
            individual = case_name
        if individual is None:save('source-matrix.json', encoded(index))
        archive = output / (mutation + '.zip')
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
            for name, body in changed.items():bundle.writestr(name, body)
        for name in changed:(candidate / name).unlink()
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():(candidate / name).write_bytes(bundle.read(name))
        if individual:
            assert verify_case(candidate / individual)['passed']
        expected = ('source matrix complete fixed 66-profile inventory' if mutation in ('missing-profile', 'repeated-profile', 'missing-scenario')
                    else 'source matrix original preexecution kernel programs and runtimes' if mutation == 'kernel'
                    else 'source matrix full cohort source and linkage binding' if mutation == 'client'
                    else 'source matrix byte-identical executable for each linkage' if mutation == 'same-linkage-executable'
                    else 'source matrix same actual musl runtime products' if mutation == 'matching-runtime-loader'
                    else 'source matrix common actual client and kernel source')
        try:
            verify(candidate, domain=domain)
        except ValueError as failure:
            assert str(failure) == expected, (mutation, str(failure))
            results.append(dict(label=mutation, rejected=True, reason=str(failure),
                                individual_case_remains_internally_consistent=individual is not None,
                                serialized_sha256=digest(archive)))
            print('SOURCE_MATRIX_CONTROL_REJECTED ' + mutation, flush=True)
        else:
            raise AssertionError('changed source matrix accepted: ' + mutation)
    assert original == {str(path.relative_to(directory)): digest(path) for path in directory.rglob('*') if path.is_file()}
    result = dict(passed=True, positive=positive, controls=results,
                  serialized_reopened_controls=len(results), originals_unchanged=True, domain=domain)
    (output / 'results.json').write_bytes(encoded(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--domain', choices=('all', 'guest'), default='all')
    args = parser.parse_args()
    result = run(args.directory, args.output, args.domain)
    print('IPV4_SOURCE_MATRIX_CONTROLS_PASS serialized_reopened=' + str(result['serialized_reopened_controls']) +
          ' originals_unchanged=1')


if __name__ == '__main__':
    main()

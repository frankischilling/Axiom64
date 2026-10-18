# SPDX-License-Identifier: GPL-3.0-or-later
"""Export real native cohorts, reject missing runtime bytes and preserve originals."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_native_inputs import audit, provider_root
from tcp_icmp_capture import require


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_audit(report, input_root):
    result = audit(report, input_root=input_root)
    for row in result['inputs']:
        require(row['sha256'] == digest(report.parent / row['inputs']),
                'reported native input fingerprint matches its actual named JSON file')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', nargs='?', type=Path, default=ROOT / 'build/tcp-fault-native-results.json')
    parser.add_argument('--output-directory', type=Path)
    parser.add_argument('--input-root', type=Path)
    args = parser.parse_args()
    source_root = args.input_root or ROOT
    checked_audit(args.report, source_root)
    out = args.output_directory or ROOT / 'build/tcp-fault-native-inputs-damaged'
    out.mkdir(parents=True, exist_ok=True)
    rows = json.loads(args.report.read_text())
    originals = {args.report: digest(args.report)}
    results = []
    with tempfile.TemporaryDirectory(prefix='axiom64-native-runtime-export-') as temporary:
        exported = Path(temporary)
        build = exported / 'build'
        build.mkdir()
        report = build / args.report.name
        report.write_text(json.dumps(rows))
        manifests = {}
        for row in rows:
            source = args.report.parent / row['inputs']
            originals[source] = digest(source)
            value = json.loads(source.read_text())
            for group in ('sources', 'products'):
                for name, expected in value[group].items():
                    actual, target = source_root / name, exported / name
                    require(digest(actual) == expected, 'original real compiled input matches its manifest')
                    originals[actual] = expected
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if not target.exists():
                        shutil.copyfile(actual, target)
            for library in value['host_libraries'].values():
                library['path'] = '/unavailable-original-host/library'
            (build / row['inputs']).write_text(json.dumps(value))
            manifests[row['linkage']] = (build / row['inputs'], value)
        checked_audit(report, exported)

        def rejected(label, expected, manifest=None, changed_product=None):
            try:
                audit(report, input_root=exported)
            except ValueError as error:
                require(expected in str(error), f'{label}: wrong rejection: {error}')
                candidate = dict(label=label, reason=str(error), report=json.loads(report.read_text()),
                                 manifest=manifest, changed_product=changed_product)
                (out / (label + '.json')).write_text(json.dumps(candidate, indent=2) + '\n')
                results.append(dict(control=label, reason=str(error)))
            else:
                raise AssertionError(label + ': damaged native runtime evidence was accepted')

        for label, changed in [('missing-profile', rows[:-1]), ('duplicate-profile', rows[:-1] + rows[:1])]:
            report.write_text(json.dumps(changed))
            rejected(label, 'all three unique native runtime input profiles')
        report.write_text(json.dumps(rows))
        path, value = manifests['native']
        for name, library in value['host_libraries'].items():
            for mutation in ('missing-retained-link', 'missing-retained-product', 'wrong-library-link', 'corrupt-library'):
                changed = deepcopy(value)
                product = exported / library['retained']
                data = product.read_bytes()
                patch = None
                if mutation == 'missing-retained-link':
                    del changed['host_libraries'][name]['retained']
                elif mutation == 'missing-retained-product':
                    del changed['products'][library['retained']]
                elif mutation == 'wrong-library-link':
                    other = next(item for key, item in value['host_libraries'].items() if key != name)
                    changed['host_libraries'][name]['retained'] = other['retained']
                else:
                    modified = bytes([data[0] ^ 1]) + data[1:]
                    product.write_bytes(modified)
                    patch = dict(path=library['retained'], offset=0, xor=1,
                                 sha256=hashlib.sha256(modified).hexdigest())
                path.write_text(json.dumps(changed))
                reason = ('both native shared libraries must be actual retained products' if mutation.startswith('missing-')
                          else 'retained native shared library fingerprint' if mutation == 'wrong-library-link'
                          else 'actual products input')
                rejected(name + '-' + mutation, reason, changed, patch)
                product.write_bytes(data)
            path.write_text(json.dumps(value))
        for linkage in ('static', 'dynamic'):
            path, value = manifests[linkage]
            for provider in ('build', 'runtime'):
                for product in ('lib/ld-musl-x86_64.so.1', 'usr/lib/libc.a'):
                    changed = deepcopy(value)
                    del changed['products'][f'{provider_root(value, provider)}/sysroot/{product}']
                    path.write_text(json.dumps(changed))
                    label = '-'.join((linkage, provider, Path(product).name, 'missing'))
                    rejected(label, 'both musl providers retain their actual loader and static library', changed)
            path.write_text(json.dumps(value))
        for linkage, (path, value) in manifests.items():
            changed = deepcopy(value)
            changed['linkage'] = 'incorrect'
            path.write_text(json.dumps(changed))
            rejected(linkage + '-wrong-linkage', 'native client, source and runtime input contract', changed)
            path.write_text(json.dumps(value))
        source = exported / 'scripts/tcp_native_inputs.py'
        data = source.read_bytes()
        source.write_bytes(b'# changed source\n' + data)
        rejected('changed-source', 'actual sources input', changed_product=dict(path='scripts/tcp_native_inputs.py', prefix='# changed source\n'))
        source.write_bytes(data)
        checked_audit(report, exported)
    require(len(results) == 22, 'all twenty-two native runtime export controls')
    require(all(digest(path) == expected for path, expected in originals.items()), 'native input controls preserve all originals')
    (out / 'results.json').write_text(json.dumps(dict(passed=True, rejected=len(results),
        original_inputs_unchanged=True, original_host_paths_unavailable=True, results=results), indent=2) + '\n')
    print('TCP_NATIVE_INPUTS_DAMAGE_PASS rejected=22 exported_actual_products=1 original_paths_unavailable=1 originals_unchanged=1')


if __name__ == '__main__':
    main()

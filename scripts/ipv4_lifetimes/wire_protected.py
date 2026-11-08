# SPDX-License-Identifier: GPL-3.0-or-later
"""Export exact wire inputs and inspect them as real root and UID65534 readers."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import signal
import stat
import subprocess
import sys
import zipfile

from fetch import ROOT
from ipv4_lifetimes import artifact_controls, controls, guest, native, native_clock, wire_artifact_controls, wire_controls, wire_matrix
from ipv4_lifetimes.protected import inventory
from ipv4_lifetimes.reader import decode, require
from ipv4_lifetimes.wire_evidence import ordinary_tree
from tcp6.inputs import digest, freeze, write

READERS = {'scripts/ipv4_lifetimes/' + name for name in
           ('controls.py', 'artifact_controls.py', 'protected.py', 'cohort.py', 'wire_log.py', 'wire_trace.py', 'wire_evidence.py', 'wire_controls.py', 'wire_matrix.py',
            'wire_artifact_controls.py', 'wire_protected.py')}


def permissions(directory):
    return {path.relative_to(directory).as_posix(): (stat.S_IMODE(path.stat().st_mode), path.stat().st_uid, path.stat().st_gid)
            for path in [directory, *ordinary_tree(directory)]}


def reader_source(destination):
    require(not (destination / 'export.json').is_symlink() and (destination / 'export.json').is_file(), 'ordinary reader export index')
    record = decode((destination / 'export.json').read_text())
    require(type(record['schema']) is int and record['schema'] == 1 and type(record['inspection_only']) is bool and
            type(record['controls']) is bool, 'fixed reader export schema and qualification mode')
    validation = destination / 'validation'
    ordinary_tree(validation)
    inputs = decode((validation / 'source/source-inputs.json').read_text())
    snapshot = record['reader_source']
    require(digest(validation / 'source/source.zip') == snapshot['source_zip_sha256'] and
            digest(validation / 'source/source-inputs.json') == snapshot['source_inputs_sha256'], 'exact independent reader source archive and inventory')
    tree = destination / 'source-tree'
    ordinary_tree(tree)
    with zipfile.ZipFile(validation / 'source/source.zip') as archive:
        require(len(archive.namelist()) == len(inputs) == snapshot['files'] and set(archive.namelist()) == set(inputs),
                'complete unique reader source inventory')
        for name, expected in inputs.items():
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and '\\' not in name and
                    not set(path.parts) & {'.git', '.local', 'build', '__pycache__'} and
                    digest(tree / name) == expected, 'every actual independent reader source file')
            require(hashlib.sha256(archive.read(name)).hexdigest() == expected, 'every exact archived reader source byte')
    require(set(inventory(tree)) == set(inputs), 'no unlisted executable reader source')
    ordinary_tree(destination / 'artifacts/source')
    producer = decode((destination / 'artifacts/source/source-inputs.json').read_text())
    if record['controls']:
        for name in ('native-controls', 'guest-controls'): ordinary_tree(destination / name / 'source')
        require(all(decode((destination / name / 'source/source-inputs.json').read_text()) == producer
                    for name in ('native-controls', 'guest-controls')), 'all control and transport producers use the same exact public source')
    differences = sorted(name for name in set(inputs) | set(producer) if inputs.get(name) != producer.get(name))
    require(differences == record['reader_differences'] and all(name in READERS or name == 'README.md' or name.startswith('docs/')
            for name in differences), 'reader revisions preserve every original runtime and build input')
    return record


def worker(destination, output, uid):
    require(os.getuid() == os.geteuid() == uid and uid in (0, 65534), 'actual requested protected identity')
    record = reader_source(destination)
    require(ROOT == destination / 'source-tree', 'reader imports only the exact separate reader source')
    if uid:
        require(os.getgid() == os.getegid() == uid and os.getgroups() == [] and
                all(not os.access(path, os.R_OK | os.X_OK) for path in
                    [record['original_directory'], *record['control_originals'].values()]), 'ordinary reader cannot reach any original capture')
    directory = destination / 'artifacts'
    before = inventory(directory)
    proof = wire_matrix.inspect(directory)
    if not record['inspection_only']:
        require(proof['passed'] is True, 'full protected qualification requires all original clocks')
    wire_faults = []
    for spec in wire_matrix.specifications():
        result = wire_controls.run(directory / spec['path'], output / spec['path'], record['inspection_only'])
        wire_faults.append(dict(profile=spec, count=result['count'], protocol_only=result['protocol_only']))
    artifacts = wire_artifact_controls.run(directory, output / 'artifact-controls')
    control_proofs, control_faults = {}, []
    if record['controls']:
        control_proofs = dict(native=native.verify(destination / 'native-controls'), guest=guest.verify(destination / 'guest-controls'))
        for spec in guest.specifications():
            name = guest.name(spec)
            result = controls.run(destination / 'guest-controls' / name / 'serial.log', output / ('controls-guest-' + name))
            control_faults.append(dict(mode='guest', profile=spec, count=result['count']))
        for profile in native.PROFILES:
            case = destination / 'native-controls' / profile
            epoch = native_clock.verify(case / 'kernel-clock.json', case / 'client.log')
            result = controls.run(case / 'client.log', output / ('controls-native-' + profile), stamp_epoch=epoch)
            control_faults.append(dict(mode='native', profile=profile, count=result['count']))
        control_proofs['artifact_controls'] = artifact_controls.run(destination / 'guest-controls', output / 'control-artifact-controls')
    require(inventory(directory) == before, 'protected worker preserves every actual input byte')
    result = dict(passed=proof['passed'], artifact_readback_passed=True, inspection_only=record['inspection_only'],
                  uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), groups=os.getgroups(), source_root=str(ROOT),
                  original_readable=os.access(record['original_directory'], os.R_OK | os.X_OK), matrix=proof,
                  controls=wire_faults, artifact_controls=artifacts, address_controls=control_proofs,
                  address_control_faults=control_faults, full_feature_acceptance=False)
    write(output / 'completed.json', result)
    return result


def produce(directory, destination, inspection_only=False, native_controls=None, guest_controls=None):
    require(os.geteuid() == 0 and 'GH_TOKEN' not in os.environ, 'credential-free root owns protected reader isolation')
    directory, destination = Path(directory).resolve(), Path(destination).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()) and destination.parent == Path('/var/tmp') and
            destination.name.startswith('axiom-ipv4-lifetime-wire-'), 'designated original and separate export directories')
    proof = wire_matrix.inspect(directory)
    if not inspection_only:
        require(proof['passed'] is True, 'full export qualification requires every original clock check')
    require((native_controls is None) == (guest_controls is None) and
            (inspection_only or native_controls is not None), 'full qualification includes both native and guest address controls')
    components = {}
    if native_controls is not None:
        native_controls, guest_controls = Path(native_controls).resolve(), Path(guest_controls).resolve()
        require(all(path.is_relative_to((ROOT / 'build').resolve()) for path in (native_controls, guest_controls)), 'designated original address-control outputs')
        native.verify(native_controls); guest.verify(guest_controls)
        components = {'native-controls': native_controls, 'guest-controls': guest_controls}
    component_inputs = {name: inventory(path) for name, path in components.items()}
    component_modes = {name: permissions(path) for name, path in components.items()}
    before, modes = inventory(directory), permissions(directory)
    destination.mkdir(mode=0o755, exist_ok=False)
    exported = destination / 'artifacts'
    shutil.copytree(directory, exported)
    require(inventory(exported) == before, 'separate export retains every original source, image and capture byte')
    for name, path in components.items():
        shutil.copytree(path, destination / name)
        require(inventory(destination / name) == component_inputs[name], 'every original address-control artifact byte is exported')
    source = destination / 'validation/source'
    source.mkdir(parents=True)
    snapshot = freeze(source)
    inputs = decode((source / 'source-inputs.json').read_text())
    tree = destination / 'source-tree'
    tree.mkdir()
    with zipfile.ZipFile(source / 'source.zip') as archive:
        require(set(archive.namelist()) == set(inputs), 'one exact independently frozen reader source')
        for name in archive.namelist():
            path = PurePosixPath(name)
            require(not path.is_absolute() and '..' not in path.parts and '\\' not in name, 'bounded reader source extraction')
        archive.extractall(tree)
    producer = decode((exported / 'source/source-inputs.json').read_text())
    differences = sorted(name for name in set(inputs) | set(producer) if inputs.get(name) != producer.get(name))
    record = dict(schema=1, original_directory=str(directory), original_export_directory=str(destination),
                  inspection_only=inspection_only, reader_source=snapshot, reader_differences=differences,
                  producer_source=decode((exported / 'inputs.json').read_text())['source'], controls=bool(components),
                  control_originals={name: str(path) for name, path in components.items()})
    write(destination / 'export.json', record)
    reader_source(destination)
    for base in (exported, tree, destination / 'validation', *[destination / name for name in components]):
        for path in ordinary_tree(base): path.chmod(0o755 if path.is_dir() else 0o444)
        base.chmod(0o755)
    (destination / 'export.json').chmod(0o444)
    environment = dict(os.environ, PYTHONPATH=str(tree / 'scripts'), PYTHONDONTWRITEBYTECODE='1')
    original_mode = stat.S_IMODE(directory.stat().st_mode)
    rows = []
    directory.chmod(0o700)
    for path in components.values(): path.chmod(0o700)
    try:
        for uid, name in ((0, 'root'), (65534, 'ordinary')):
            output = destination / name
            output.mkdir(mode=0o700)
            if uid: os.chown(output, uid, uid)
            command = [sys.executable, '-B', '-m', 'ipv4_lifetimes.wire_protected', str(destination), str(output), '--worker', '--uid', str(uid)]
            if uid: command = ['setpriv', '--reuid=65534', '--regid=65534', '--clear-groups', *command]
            with (destination / (name + '.log')).open('xb') as log:
                process = subprocess.Popen(command, cwd=tree, env=environment, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
                timed_out = False
                try:
                    process.wait(timeout=300)
                except subprocess.TimeoutExpired:
                    timed_out = True; process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
            saved = decode((output / 'completed.json').read_text()) if (output / 'completed.json').is_file() else None
            rows.append(dict(identity=name, uid=uid, returncode=process.returncode, timed_out=timed_out,
                             readback=saved, log_sha256=digest(destination / (name + '.log'))))
            write(destination / 'processes.json', rows)
    finally:
        directory.chmod(original_mode)
        for name, path in components.items(): path.chmod(component_modes[name]['.'][0])
    require(inventory(directory) == inventory(exported) == before and permissions(directory) == modes,
            'both readers preserve every original artifact byte, owner and permission')
    require(all(inventory(path) == inventory(destination / name) == component_inputs[name] and permissions(path) == component_modes[name]
                for name, path in components.items()), 'both readers preserve all original address-control bytes, owners and permissions')
    require(all(row['returncode'] == 0 and row['timed_out'] is False and row['readback'] is not None and
                row['readback']['artifact_readback_passed'] is True and row['readback']['uid'] == row['readback']['euid'] == row['uid']
                for row in rows), 'both actual protected readers complete all artifact and corruption checks')
    result = dict(passed=all(row['readback']['passed'] for row in rows), artifact_readback_passed=True,
                  inspection_only=inspection_only, artifacts=before, identities=rows, profiles_per_identity=22 if components else 11,
                  wire_profiles_per_identity=11, address_control_profiles_per_identity=11 if components else 0,
                  protocol_controls_per_identity=11 * len(wire_controls.NAMES), artifact_controls_per_identity=len(wire_artifact_controls.NAMES),
                  original_permissions_restored=True, originals_unchanged=True, reader_source=snapshot,
                  original_export_directory=str(destination), full_feature_acceptance=False, controls=bool(components),
                  address_control_artifacts=component_inputs)
    write(destination / 'completed.json', result)
    if not inspection_only: verify(destination)
    return result


def verify(destination):
    destination = Path(destination).resolve()
    record = reader_source(destination)
    saved = decode((destination / 'completed.json').read_text())
    require(record['inspection_only'] is False and saved['inspection_only'] is False and saved['passed'] is True and
            saved['artifact_readback_passed'] is True and saved['profiles_per_identity'] == 22 and saved['wire_profiles_per_identity'] == 11 and
            saved['address_control_profiles_per_identity'] == 11 and
            record['controls'] is True and saved['controls'] is True and
            saved['reader_source'] == record['reader_source'] and inventory(destination / 'artifacts') == saved['artifacts'],
            'full protected export passes original clocks and retains every original artifact')
    proof = wire_matrix.verify(destination / 'artifacts')
    control_proofs = dict(native=native.verify(destination / 'native-controls'), guest=guest.verify(destination / 'guest-controls'))
    require(all(inventory(destination / name) == value for name, value in saved['address_control_artifacts'].items()) and
            set(saved['address_control_artifacts']) == {'native-controls', 'guest-controls'}, 'complete original native and guest control export')
    require([row['identity'] for row in saved['identities']] == ['root', 'ordinary'] and
            [row['uid'] for row in saved['identities']] == [0, 65534] and
            all(type(row['uid']) is int for row in saved['identities']), 'both required actual reader identities')
    expected_faults = ([dict(mode='guest', profile=spec, count=len(controls.NAMES)) for spec in guest.specifications()] +
                       [dict(mode='native', profile=profile, count=len(controls.NAMES)) for profile in native.PROFILES])
    for row in saved['identities']:
        result = decode((destination / row['identity'] / 'completed.json').read_text())
        require(result == row['readback'] and row['returncode'] == 0 and row['timed_out'] is False and
                row['log_sha256'] == digest(destination / (row['identity'] + '.log')) and result['passed'] is True and
                result['uid'] == result['euid'] == row['uid'] and result['matrix'] == proof and
                len(result['controls']) == 11 and all(value['count'] == len(wire_controls.NAMES) + len(wire_controls.CLOCK_NAMES) and
                value['protocol_only'] is False for value in result['controls']) and
                result['artifact_controls']['count'] == len(wire_artifact_controls.NAMES) and
                all(result['address_controls'][name] == value for name, value in control_proofs.items()) and
                result['address_control_faults'] == expected_faults and
                result['address_controls']['artifact_controls']['count'] == len(artifact_controls.NAMES), 'complete original protected reader and rejection inventory')
        require([value['profile'] for value in result['controls']] == wire_matrix.specifications() and
                result['source_root'] == str(PurePosixPath(record['original_export_directory']) / 'source-tree') and
                type(result['uid']) is int and type(result['euid']) is int and
                (row['uid'] == 0 or (result['gid'] == 65534 and result['groups'] == [] and result['original_readable'] is False)),
                'actual frozen reader source, ordered profile coverage and ordinary credential isolation')
        output = destination / row['identity']
        for spec in wire_matrix.specifications():
            replay = wire_controls.reopen(destination / 'artifacts' / spec['path'], output / spec['path'])
            require(replay['count'] == len(wire_controls.NAMES) + len(wire_controls.CLOCK_NAMES) and replay['protocol_only'] is False,
                    'every published original protocol and clock fault is independently rejected')
        wire_artifact_controls.run(destination / 'artifacts', output / 'artifact-controls', reopening=True)
        for spec in guest.specifications():
            name = guest.name(spec)
            controls.reopen(destination / 'guest-controls' / name / 'serial.log', output / ('controls-guest-' + name))
        for profile in native.PROFILES:
            case = destination / 'native-controls' / profile
            epoch = native_clock.verify(case / 'kernel-clock.json', case / 'client.log')
            controls.reopen(case / 'client.log', output / ('controls-native-' + profile), stamp_epoch=epoch)
        artifact_controls.reopen(destination / 'guest-controls', output / 'control-artifact-controls')
    return dict(passed=True, profiles=22, wire_profiles=11, address_control_profiles=11, identities=2, ordinary_uid=65534,
                controls_per_identity=11 * (len(wire_controls.NAMES) + len(wire_controls.CLOCK_NAMES)),
                address_control_faults_per_identity=11 * len(controls.NAMES),
                artifact_controls_per_identity=len(wire_artifact_controls.NAMES) + len(artifact_controls.NAMES), full_feature_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('destination', type=Path, nargs='?')
    parser.add_argument('--worker', action='store_true')
    parser.add_argument('--uid', type=int)
    parser.add_argument('--native-controls', type=Path)
    parser.add_argument('--guest-controls', type=Path)
    parser.add_argument('--inspect-rejected', action='store_true', help='retain failed clock qualification while checking artifact readability')
    args = parser.parse_args()
    def interrupted(signum, frame):
        raise KeyboardInterrupt('protected lifetime reader interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    if args.worker:
        require(args.destination is not None and args.uid in (0, 65534), 'explicit protected worker output and identity')
        result = worker(args.directory.resolve(), args.destination.resolve(), args.uid)
    elif args.destination is not None:
        result = produce(args.directory, args.destination, args.inspect_rejected, args.native_controls, args.guest_controls)
    else:
        require(not args.inspect_rejected, 'reopening qualification never waives clock failures')
        result = verify(args.directory)
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()

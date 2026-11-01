# SPDX-License-Identifier: GPL-3.0-or-later
"""Run complete finite-address qualification in the existing IPv4 CI job."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

from fetch import ROOT
from ipv4_lifetimes.reader import decode, require
from ipv4_lifetimes.wire_evidence import source
from ipv4_lifetimes import wire_protected
from tcp6.inputs import digest, freeze, write

CONTROL_NATIVE = 'ipv4-address-lifetimes-native'
CONTROL_GUEST = 'ipv4-address-lifetimes-guest'
WIRE = 'ipv4-address-lifetimes-wire'
AUDIT = 'ipv4-address-lifetimes-audit'
EXPORT = Path('/var/tmp/axiom-ipv4-lifetime-wire-export')


def preservation(directory):
    result = {}
    for path in [directory, *directory.rglob('*')]:
        info = path.lstat()
        value = dict(mode=stat.S_IMODE(info.st_mode))
        if path.is_symlink(): value['link'] = os.readlink(path)
        elif path.is_file(): value.update(bytes=info.st_size, sha256=digest(path))
        else: require(path.is_dir(), 'only retained files, directories and diagnostic links')
        result[path.relative_to(directory).as_posix()] = value
    return result


def retain_export():
    if not EXPORT.exists(): return None
    target = ROOT / 'build' / AUDIT / 'wire'
    require(EXPORT.parent == Path('/var/tmp') and not EXPORT.is_symlink() and
            target.resolve().is_relative_to((ROOT / 'build').resolve()) and not target.exists(), 'exact owned publication move targets')
    before = preservation(EXPORT)
    target.parent.mkdir(exist_ok=True)
    shutil.move(str(EXPORT), target)
    require(preservation(target) == before, 'retained protected export bytes, modes and diagnostic aliases')
    # The recorded readback ran before publication normalizes archive permissions.
    for path in [target, *target.rglob('*')]:
        if not path.is_symlink(): path.chmod(0o755 if path.is_dir() else 0o444)
    write(target.parent / 'retained.json', dict(passed=True, original=str(EXPORT), retained=str(target), original_inventory=before))
    return dict(directory=str(target), files=len(before))


def command(directory, name, arguments, timeout):
    began = time.monotonic_ns()
    with (directory / (name + '.log')).open('xb') as log:
        process = subprocess.Popen(arguments, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # Matrix cancellation owns its separately grouped capture children.
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try: process.wait(timeout=20)
                except subprocess.TimeoutExpired: os.killpg(process.pid, signal.SIGKILL); process.wait()
            else:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            result = dict(name=name, command=arguments, returncode=process.returncode, timed_out=timed_out,
                          elapsed_ns=time.monotonic_ns() - began, log_sha256=digest(directory / (name + '.log')))
            write(directory / (name + '.json'), result)
    print(json.dumps(result), flush=True)
    return result


def verify(directory):
    directory = Path(directory).resolve()
    index = decode((directory / 'completed.json').read_text())
    require(index['passed'] is True and [row['name'] for row in index['commands']] == ['native-controls', 'guest-controls', 'wire', 'protected'] and
            all(type(row['returncode']) is int and row['returncode'] == 0 and row['timed_out'] is False and
                row['log_sha256'] == digest(directory / (row['name'] + '.log')) for row in index['commands']), 'every complete finite-address cohort command passed')
    inputs = source(directory, index['source'])
    require(all(inputs[name] == digest(ROOT / name) for name in
                ('scripts/ipv4_lifetimes/cohort.py', '.github/workflows/build.yml', 'Makefile')), 'same complete CI orchestration and build inputs')
    export = directory.parent / AUDIT / 'wire'
    require(inputs == decode((export / 'artifacts/source/source-inputs.json').read_text()), 'every cohort and runtime source byte matches')
    proof = wire_protected.verify(export)
    require(proof == index['readback'], 'same original complete protected address and transport proof')
    return dict(passed=True, wire_profiles=11, address_control_profiles=11, protected_identities=2,
                readback=proof, observations_rescaled=False, full_feature_acceptance=False)


def produce(directory):
    require(os.geteuid() == 0 and 'GH_TOKEN' not in os.environ, 'credential-free actual root owns complete cohort qualification')
    directory = Path(directory).resolve()
    require(directory.parent == (ROOT / 'build').resolve() and directory.name == 'ipv4-address-lifetimes-cohort' and not EXPORT.exists(),
            'one fresh designated cohort and export root')
    directory.mkdir(exist_ok=False)
    targets = [f'build/{prefix}-{profile}' for prefix in ('ipv4-address-lifetimes', 'ipv4-lifetime-wire')
               for profile in ('native', 'static', 'dynamic')]
    with (directory / 'build.log').open('xb') as log:
        subprocess.run(['make', '-j2', 'build/axiom64.elf', 'build/init', 'busybox', *targets], cwd=ROOT,
                       stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, check=True)
    (directory / 'source').mkdir()
    snapshot = freeze(directory / 'source')
    commands = []
    try:
        for name, module, output, timeout in (
                ('native-controls', 'native', CONTROL_NATIVE, 480), ('guest-controls', 'guest', CONTROL_GUEST, 600),
                ('wire', 'wire_matrix', WIRE, 2400)):
            commands.append(command(directory, name, [sys.executable, '-B', '-m', 'ipv4_lifetimes.' + module,
                str(ROOT / 'build' / output), '--produce'], timeout))
        if all(row['returncode'] == 0 and row['timed_out'] is False for row in commands):
            commands.append(command(directory, 'protected', [sys.executable, '-B', '-m', 'ipv4_lifetimes.wire_protected',
                str(ROOT / 'build' / WIRE), str(EXPORT), '--native-controls', str(ROOT / 'build' / CONTROL_NATIVE),
                '--guest-controls', str(ROOT / 'build' / CONTROL_GUEST)], 900))
    finally:
        retained = retain_export()
        write(directory / 'commands.json', dict(commands=commands, retained_export=retained))
    require(len(commands) == 4 and all(row['returncode'] == 0 and row['timed_out'] is False for row in commands),
            'every native, guest, transport and protected gate must pass without retry')
    proof = wire_protected.verify(ROOT / 'build' / AUDIT / 'wire')
    require(decode((directory / 'source/source-inputs.json').read_text()) ==
            decode((ROOT / 'build' / AUDIT / 'wire/artifacts/source/source-inputs.json').read_text()), 'unchanged complete cohort source')
    write(directory / 'completed.json', dict(passed=True, source=snapshot, commands=commands, readback=proof))
    return dict(passed=True, wire_profiles=11, address_control_profiles=11, protected_identities=2,
                readback=proof, observations_rescaled=False, full_feature_acceptance=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--produce', action='store_true')
    args = parser.parse_args()
    def interrupted(signum, frame): raise KeyboardInterrupt('IPv4 address lifetime cohort interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    print(json.dumps(produce(args.directory) if args.produce else verify(args.directory)), flush=True)


if __name__ == '__main__':
    main()

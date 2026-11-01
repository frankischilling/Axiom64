# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen published routing evidence and reject faults as root and an ordinary user."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import zipfile

from fetch import ROOT
from ipv4_source_route import faults, matrix
from ipv4_source_route.controls import require
from tcp6.inputs import digest, write


def run(directory, output, control_directory):
    directory, output, control_directory = (Path(value).resolve() for value in (directory, output, control_directory))
    require(os.geteuid() == 0 and output.is_relative_to((ROOT / 'build').resolve()), 'root audit in designated ignored output')
    output.mkdir(parents=True, exist_ok=False)
    original = matrix.verify(directory)
    from ipv4_source_route.evidence import verify as verify_controls
    control_proof = verify_controls(control_directory)
    require(json.loads((control_directory / 'source-inputs.json').read_text()) ==
            json.loads((directory / 'source/source-inputs.json').read_text()), 'same complete syscall and wire source cohort')
    original_files = {path.relative_to(directory).as_posix(): digest(path)
                      for path in directory.rglob('*') if path.is_file()}
    with tempfile.TemporaryDirectory(prefix='axiom64-routing-audit-') as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o755)
        public_source = scratch / 'source'
        public_source.mkdir()
        # matrix.verify validated every bounded archive name and byte before extraction.
        with zipfile.ZipFile(directory / 'source/source.zip') as archive:
            archive.extractall(public_source)
        evidence = scratch / 'evidence'
        shutil.copytree(directory, evidence, copy_function=os.link)
        syscall_evidence = scratch / 'syscalls'
        shutil.copytree(control_directory, syscall_evidence, copy_function=os.link)
        require(all(not path.is_symlink() and (not path.is_file() or path.stat().st_mode & 4)
                    for path in evidence.rglob('*')), 'ordinary reader can open every retained product without changing it')
        positive = scratch / 'positive'
        positive.mkdir()
        request = dict(kind='matrix', directory=str(evidence))
        identities = [faults.invoke(request, positive, public_source, ordinary) for ordinary in (False, True)]
        require(all(value['accepted'] is True for value in identities), 'both actual identities accept the complete original matrix')
        shutil.copytree(positive, output / 'positive')
        control_positive = scratch / 'control-positive'
        control_positive.mkdir()
        control_identities = [faults.invoke(dict(kind='controls', directory=str(syscall_evidence)),
                              control_positive, public_source, ordinary) for ordinary in (False, True)]
        require(all(value['accepted'] is True for value in control_identities), 'both actual identities reopen every syscall profile')
        shutil.copytree(control_positive, output / 'control-positive')
        artifact_faults = faults.audit(evidence, scratch / 'faults', public_source)
        shutil.copytree(scratch / 'faults', output / 'faults')
        controls = []
        user = pwd.getpwnam('nobody')
        for ordinary in (False, True):
            identity = 'ordinary' if ordinary else 'root'
            workspace = scratch / (identity + '-controls')
            workspace.mkdir()
            if ordinary:
                os.chown(workspace, user.pw_uid, user.pw_gid)
            for phase in matrix.PHASES:
                target = workspace / phase
                command = [sys.executable, '-B', '-m', 'ipv4_source_route.wire_controls',
                           str(evidence / (phase + '-native-static')),
                           str(evidence / (phase + '-guest-static-bios-modern')), '--output', str(target)]
                if phase != 'packets':
                    command += ['--' + phase]
                if ordinary:
                    command = ['runuser', '-u', 'nobody', '--', *command]
                with (output / (identity + '-' + phase + '.log')).open('xb') as stream:
                    process = subprocess.run(command, cwd=scratch, stdin=subprocess.DEVNULL, stdout=stream,
                        stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONPATH=str(public_source / 'scripts')), timeout=300)
                require(process.returncode == 0, 'actual identity rejected all serialized wire faults: ' + identity + '/' + phase)
                value = json.loads((target / 'results.json').read_text())
                require(value['passed'] is True and value['original_evidence_unchanged'] is True,
                        'wire control reader completed with original evidence intact')
                controls.append(dict(identity=identity, phase=phase, serialized_reopened_controls=value['serialized_reopened_controls']))
            command = [sys.executable, '-B', '-m', 'ipv4_source_route.controls_test', str(syscall_evidence),
                       '--output', str(workspace / 'syscalls')]
            if ordinary:
                command = ['runuser', '-u', 'nobody', '--', *command]
            with (output / (identity + '-syscalls.log')).open('xb') as stream:
                process = subprocess.run(command, cwd=scratch, stdin=subprocess.DEVNULL, stdout=stream,
                    stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONPATH=str(public_source / 'scripts')), timeout=180)
            require(process.returncode == 0, 'actual identity rejects all serialized syscall faults')
            syscall_faults = json.loads((workspace / 'syscalls/results.json').read_text())
            controls.append(dict(identity=identity, phase='syscalls', serialized_reopened_controls=syscall_faults['serialized_reopened_controls']))
            shutil.copytree(workspace, output / (identity + '-controls'))
    require(original_files == {path.relative_to(directory).as_posix(): digest(path)
                              for path in directory.rglob('*') if path.is_file()}, 'all original matrix artifacts remain byte-identical')
    proof = dict(passed=True, matrix=original, actual_identities=identities,
                 syscall_controls=control_proof, syscall_reader_identities=control_identities,
                 artifact_faults=artifact_faults['serialized_reopened_faults'], artifact_fault_identities=2,
                 wire_controls=controls, original_artifacts_preserved=True)
    write(output / 'verified.json', proof)
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--controls', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.directory, args.output, args.controls)), flush=True)


if __name__ == '__main__':
    main()

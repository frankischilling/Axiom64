# SPDX-License-Identifier: GPL-3.0-or-later
"""Run paired network VM suites with independent processes and generated files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[2]
SUITE = re.compile(r'(protocol|link)-(bios|uefi)-(modern|legacy)-lane([01])')
NORMAL = re.compile(r'normal-init-(bios|uefi)')
NORMAL_SCENARIOS = ('no-nic', 'no-server', 'missing', 'healthy')


def parameters(suite):
    normal = NORMAL.fullmatch(suite)
    if normal:
        return 'normal', ['--firmware', normal.group(1)]
    match = SUITE.fullmatch(suite)
    if match is None:
        raise ValueError(f'unsupported paired network suite: {suite}')
    kind, firmware, transport, affected = match.groups()
    return kind, ['--firmware', firmware, '--transport', transport, '--affected', affected]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def normal_cases(build, firmware, transport, scenarios, root_type):
    rows = json.loads((build / f'normal-init-{firmware}-results.json').read_text())
    roots = ('ram', 'ext2') if root_type in (None, 'both') else (root_type,)
    expected = {(scenario, firmware, transport, root) for scenario in scenarios for root in roots}
    actual = [(row['scenario'], row['firmware'], row['transport'], row['root']) for row in rows]
    if (len(actual) != len(expected) or set(actual) != expected or
            any(row['passed'] is not True for row in rows)):
        raise ValueError('normal-init case coverage or actual acceptance is incomplete')
    return rows


def retain_normal_fixtures(root, workspace, suite, worker, previous):
    """Move new original fixtures intact; unlink aliases only after byte equality."""
    build = workspace / 'build'
    destination = root / 'build' / 'normal-init-workers' / suite / worker
    if not destination.resolve().is_relative_to((root / 'build').resolve()):
        raise ValueError('normal fixture destination escapes the owned build directory')
    destination.mkdir(parents=True, exist_ok=True)
    retained = {}
    for source in sorted(build.glob('normal-init-login-*')):
        if source.name in previous:
            continue
        if source.is_symlink() or not source.is_dir() or not source.resolve().is_relative_to(build.resolve()):
            raise ValueError('normal fixture is outside the worker build directory')
        target = destination / source.name
        if target.exists():
            raise ValueError('normal fixture retention target already exists')
        originals = {}
        for path in source.rglob('*'):
            if path.is_symlink():
                raise ValueError('normal fixture contains an unexpected symbolic link')
            if path.is_file():
                originals[path.relative_to(source)] = dict(bytes=path.stat().st_size, sha256=digest(path))
        shutil.move(str(source), target)
        for name, expected in originals.items():
            path = target / name
            if path.stat().st_size != expected['bytes'] or digest(path) != expected['sha256']:
                raise ValueError('retained normal fixture bytes changed')
            original = source.relative_to(build) / name
            retained[original.as_posix()] = dict(path=path.relative_to(root).as_posix(), **expected)
    aliases = []
    for name, original in [('axiom64-normal-init-ram.iso', 'axiom64-normal-init-ram.iso'),
                           ('axiom64-normal-init-ext2.iso', 'axiom64-normal-init-ext2.iso'),
                           ('root-disk.raw', 'seed.raw')]:
        alias = build / name
        copies = [value for key, value in retained.items() if Path(key).name == original]
        if alias.exists() and len(copies) == 1:
            saved, = copies
            if alias.is_symlink() or alias.stat().st_size != saved['bytes'] or digest(alias) != saved['sha256']:
                raise ValueError('normal fixture alias differs from its retained original')
            aliases.append(dict(original=name, retained=saved['path'], sha256=saved['sha256']))
            alias.unlink()
    return retained, aliases


def retain_unverified_normal_fixtures(workspace, destination, previous):
    """Keep original failed outputs when normal retention cannot finish."""
    build = workspace / 'build'
    sources = [path for path in build.glob('normal-init-login-*') if path.name not in previous]
    sources += [build / name for name in ('axiom64-normal-init-ram.iso',
                 'axiom64-normal-init-ext2.iso', 'root-disk.raw') if (build / name).exists()]
    if not sources:
        return None
    path = destination / f'unverified-normal-fixtures-{time.monotonic_ns()}.tar.gz'
    with tarfile.open(path, 'x:gz', compresslevel=1, dereference=False) as retained:
        for source in sources:
            retained.add(source, arcname=source.name)
    with tarfile.open(path, 'r:gz') as retained:
        members = [member.name for member in retained]
    return dict(path=path, bytes=path.stat().st_size, sha256=digest(path), members=members,
                accepted=False, reason='normal fixture retention failed; original outputs are unverified')


def capture(process, destination, worker, failures):
    try:
        with destination.open('wb') as output:
            for line in process.stdout:
                output.write(line)
                output.flush()
                print(f'{worker}: {line.decode("utf-8", errors="replace").rstrip()}', flush=True)
    except Exception as failure:
        failures.append(f'{worker}: {type(failure).__name__}: {failure}')


def stop(process):
    # A worker may have exited while leaving a QEMU descendant in its session.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # Reap descendants too, including those that ignored TERM after their parent exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_pair(root, archive, temporary_parent, suite, scenarios=None, root_type=None):
    kind, arguments = parameters(suite)
    if root_type is not None and (kind != 'normal' or root_type not in ('ram', 'ext2', 'both')):
        raise ValueError('root selection is only supported for normal-init profiles')
    if scenarios is not None and (not scenarios or len(set(scenarios)) != len(scenarios)):
        raise ValueError('scenario selection must be nonempty and unique')
    if root_type is not None:
        arguments += ['--root', root_type]
    if scenarios is not None:
        arguments += ['--scenario', *scenarios]
    choices = ('modern', 'legacy') if kind == 'normal' else ('static', 'dynamic')
    root, archive = Path(root).resolve(), Path(archive).resolve()
    if not archive.is_file():
        raise ValueError(f'test input archive is missing: {archive}')
    evidence = root / 'build' / 'paired-network' / suite
    evidence.mkdir(parents=True, exist_ok=True)
    workers, readers, records = {}, {}, {}
    capture_failures = []
    retention_failures = []
    normal_inputs = {}
    error = None
    began = time.monotonic()
    temporary = tempfile.mkdtemp(prefix=f'{suite}-', dir=temporary_parent)
    keep_temporary = False
    report = None
    try:
        dynamic = Path(temporary)
        try:
            subprocess.run(['tar', '-xzf', str(archive), '-C', str(dynamic)], check=True)
            if kind == 'normal':
                for name in ('axiom64.elf', 'rootfs.cpio'):
                    original = root / 'build' / name
                    copied = dynamic / 'build' / name
                    if original.is_symlink() or copied.is_symlink():
                        raise ValueError('normal workers require regular prepared kernel and root inputs')
                    expected = digest(original)
                    if expected != digest(copied):
                        raise ValueError('normal workers require identical prepared kernel and root inputs')
                    normal_inputs[name] = expected
            for worker, workspace in zip(choices, (root, dynamic)):
                output = evidence / worker
                output.mkdir(exist_ok=True)
                script = 'normal_manager_test.py' if kind == 'normal' else f'manager_{kind}_test.py'
                selection = '--transport' if kind == 'normal' else '--linkage'
                command = [sys.executable, '-u', str(workspace / 'scripts' / script),
                           *arguments, selection, worker]
                records[worker] = dict(workspace=str(workspace), command=command,
                                        evidence=str(output.relative_to(root)), returncode=None)
                if kind == 'normal':
                    records[worker]['previous_fixture_directories'] = [
                        path.name for path in (workspace / 'build').glob('normal-init-login-*')]
                print(f'Starting {suite} {worker} in {workspace}', flush=True)
                process = subprocess.Popen(command, cwd=workspace, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                workers[worker] = process
                reader = threading.Thread(target=capture,
                                          args=(process, output / 'worker.log', worker, capture_failures))
                reader.start()
                readers[worker] = reader
            for worker, process in workers.items():
                records[worker]['returncode'] = process.wait()
        except BaseException as failure:
            error = f'{type(failure).__name__}: {failure}'
            print(error, file=sys.stderr, flush=True)
        finally:
            for process in workers.values():
                stop(process)
            for worker, process in workers.items():
                readers[worker].join()
                process.stdout.close()
                records[worker]['returncode'] = process.returncode
            for worker, record in records.items():
                destination = root / record['evidence']
                build = Path(record['workspace']) / 'build'
                pattern = 'normal-init-*' if kind == 'normal' else f'manager-{kind}-*'
                for source in build.glob(pattern):
                    if source.is_file() and source.suffix in ('.json', '.log', '.png', '.pcap'):
                        try:
                            shutil.copy2(source, destination / source.name)
                        except OSError as failure:
                            capture_failures.append(f'{worker}: evidence copy: {failure}')
                            keep_temporary = True
                if kind == 'normal':
                    try:
                        fixtures, aliases = retain_normal_fixtures(root, Path(record['workspace']), suite,
                            worker, record['previous_fixture_directories'])
                        record.update(fixtures=fixtures, retired_duplicate_aliases=aliases)
                        record['normal_cases'] = normal_cases(build, NORMAL.fullmatch(suite).group(1),
                            worker, scenarios or NORMAL_SCENARIOS, root_type)
                    except Exception as failure:
                        retention_failures.append(f'{worker}: {type(failure).__name__}: {failure}')
                        try:
                            saved = retain_unverified_normal_fixtures(Path(record['workspace']), destination,
                                record['previous_fixture_directories'])
                            if saved:
                                saved['path'] = saved['path'].relative_to(root).as_posix()
                                record['unverified_fixture_archive'] = saved
                        except Exception as backup_failure:
                            keep_temporary = True
                            record['fixture_backup_error'] = f'{type(backup_failure).__name__}: {backup_failure}'
            success = error is None and not capture_failures and not retention_failures and set(records) == set(choices) and all(
                record['returncode'] == 0 for record in records.values())
            report = dict(suite=suite, success=success, error=error, capture_failures=capture_failures,
                          retention_failures=retention_failures,
                          normal_input_sha256=normal_inputs,
                          preserved_temporary_workspace=str(dynamic) if keep_temporary else None,
                          elapsed_seconds=round(time.monotonic() - began, 3), workers=records)
            (evidence / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    finally:
        if not keep_temporary:
            target = Path(temporary)
            parent = Path(temporary_parent or tempfile.gettempdir()).resolve()
            if target.is_symlink() or target.resolve().parent != parent or not target.name.startswith(suite + '-'):
                raise ValueError('temporary cleanup target differs from the created worker workspace')
            try:
                shutil.rmtree(target)
            except OSError as failure:
                success = False
                if report is not None:
                    report.update(success=False, cleanup_error=f'{type(failure).__name__}: {failure}',
                                  preserved_temporary_workspace=str(target))
                    (evidence / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if success else 1


def interrupted(signum, frame):
    raise InterruptedError(f'received signal {signum}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', required=True)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--temporary-parent', type=Path)
    parser.add_argument('--scenario', nargs='+', help='select a focused profile; CI runs every scenario')
    parser.add_argument('--root', dest='root_type', choices=('ram', 'ext2', 'both'),
                        help='select a focused normal-init root profile')
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        return run_pair(ROOT, args.archive, args.temporary_parent, args.suite,
                        args.scenario, args.root_type)
    except ValueError as failure:
        parser.error(str(failure))


if __name__ == '__main__':
    raise SystemExit(main())

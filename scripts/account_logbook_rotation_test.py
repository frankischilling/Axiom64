#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain real native rotation, live-lease and every-publication-boundary controls."""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import tarfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ['userspace/accounts/' + name for name in (
    'store.c', 'store.h', 'database.c', 'database.h', 'record.c', 'record.h',
    'protected.c', 'protected.h', 'login_record.c', 'login_record.h', 'logbook.c',
    'logbook.h', 'logbook_rotation.c', 'logbook_internal.h', 'auth.h', 'password.h')]
CLIENT = 'userspace/tests/security/account-logbook-rotation.c'
HOLDERS = 'userspace/tests/security/account-logbook-rotation-holders.c'
INPUTS = [*SOURCES, CLIENT, HOLDERS, 'scripts/account_logbook_rotation_test.py']


def environment():
    result = os.environ.copy()
    for key in ('CC', 'CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CPATH', 'C_INCLUDE_PATH', 'LIBRARY_PATH',
                'CPLUS_INCLUDE_PATH', 'GCC_EXEC_PREFIX', 'COMPILER_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH'):
        result.pop(key, None)
    return result


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def execute_command(command, log, expected):
    started = time.monotonic_ns()
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True, env=environment())
        try:
            process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    text = log.read_text()
    row = dict(command=command, returncode=process.returncode, timed_out=timed_out,
               elapsed_ns=time.monotonic_ns() - started, log=log.name, log_sha256=digest(log),
               passed=not timed_out and process.returncode == 0 and text.splitlines().count(expected) == 1
               and 'ACCOUNT_ROTATION_FAIL' not in text and 'ACCOUNT_ROTATION_HOLDERS_FAIL' not in text)
    return row, text


def execute(program, fixtures, scenario, mode, phase, directory, case_name=None):
    name = case_name or f'{scenario}-{mode}-{phase}'
    command = [str(program), str(fixtures / name), scenario, str(mode), str(phase)]
    expected = f'ACCOUNT_ROTATION_PASS scenario={scenario} mode={mode} phase={phase}'
    row, text = execute_command(command, directory / (name + '.log'), expected)
    if mode:
        injections = re.findall(r'^ACCOUNT_ROTATION_INJECTED mode=(\d+) phase=(\d+) operation=(\w+)$',
                                text, re.MULTILINE)
        row['injections'] = injections
        row['passed'] = row['passed'] and len(injections) == 1 and \
            injections[0][:2] == (str(mode), str(phase))
        if mode >= 5:
            pieces = re.findall(r'^ACCOUNT_ROTATION_PARTIAL mode=(\d+) phase=(\d+) actual=(\d+) expected=(\d+)$',
                                text, re.MULTILINE)
            row['partial_writes'] = pieces
            row['passed'] = row['passed'] and len(pieces) == 1 and \
                pieces[0][:2] == (str(mode), str(phase)) and 0 < int(pieces[0][2]) < int(pieces[0][3])
    return row, text


def reseal(data):
    struct.pack_into('<I', data, 12, 0)
    struct.pack_into('<I', data, 12, zlib.crc32(data))
    return data


def metadata_negatives(program, fixtures, directory):
    source = fixtures / 'metadata-0-0'
    archive = 'archive-0000000000000001'
    variants = []
    for name, offset, value in [('zero-generation', 16, 0), ('wrong-generation', 16, 3),
                                ('too-many-carries', 24, 5), ('wrong-carry-count', 24, 1),
                                ('wrong-event-base', 32, 9)]:
        data = bytearray((source / 'state').read_bytes())
        struct.pack_into('<Q', data, offset, value)
        variants.append((name, 'state', bytes(reseal(data))))
    for name, file in [('short-state', 'state'), ('short-archive-state', archive + '/state')]:
        variants.append((name, file, (source / file).read_bytes()[:-1]))
    for name, file in [('partial-archive-journal', archive + '/journal'),
                       ('extra-archive-wtmp', archive + '/wtmp'),
                       ('extra-archive-btmp', archive + '/btmp'),
                       ('extra-archive-auth', archive + '/auth.log')]:
        variants.append((name, file, (source / file).read_bytes() + b'partial'))
    data = bytearray((source / archive / 'state').read_bytes())
    struct.pack_into('<Q', data, 32, 1)
    variants.append(('wrong-archive-event-base', archive + '/state', bytes(reseal(data))))
    original = bytearray((source / archive / 'journal').read_bytes())
    variants.append(('oversized-archive-journal', archive + '/journal',
                     bytes(original) + b'x' * 129, errno.EFBIG))
    data = bytearray(original)
    data[432] ^= 1
    data[:448] = reseal(bytearray(data[:448]))
    variants.append(('changed-archive-carry-token', archive + '/journal', bytes(data)))
    data = bytearray(original)
    data[448 + 432:448 + 448] = data[432:448]
    data[448:896] = reseal(bytearray(data[448:896]))
    variants.append(('duplicate-archive-start-token', archive + '/journal', bytes(data)))
    data = bytearray((source / 'journal').read_bytes())
    for index in (0, 3):
        data[index * 448 + 432] ^= 1
        data[index * 448:(index + 1) * 448] = reseal(bytearray(data[index * 448:(index + 1) * 448]))
    variants.append(('changed-current-carry-and-end-token', 'journal', bytes(data)))
    before = (source / archive / 'state').read_bytes()
    after = (source / 'state').read_bytes()
    current = (source / 'journal').read_bytes()
    marker = bytearray(struct.pack('<4I', 0x52423641, 1, 112, 0) + before + after +
                       struct.pack('<QII', 8, zlib.crc32(original), zlib.crc32(current[:896])))
    variants.append(('partial-marker', 'rotation', bytes(marker[:-1])))
    for name, offset, value, format in [('marker-frame-bound', 96, 9, '<Q'),
                                       ('marker-old-source-crc', 104, zlib.crc32(original) ^ 1, '<I'),
                                       ('marker-new-source-crc', 108, zlib.crc32(current[:896]) ^ 1, '<I'),
                                       ('marker-generation-step', 72, 3, '<Q'),
                                       ('marker-carry-count', 80, 3, '<Q')]:
        data = bytearray(marker)
        struct.pack_into(format, data, offset, value)
        data[56:96] = reseal(bytearray(data[56:96]))
        variants.append((name, 'rotation', bytes(reseal(data))))
    rows = []
    for variant in variants:
        name, file, data = variant[:3]
        expected_error = variant[3] if len(variant) == 4 else errno.EUCLEAN
        case_name = 'negative-' + name
        target = fixtures / case_name
        shutil.copytree(source, target)
        changed = target / file
        changed.write_bytes(data)
        changed.chmod(0o600 if file not in (archive + '/wtmp',) else 0o644)
        before_files = {path.relative_to(target).as_posix(): digest(path)
                        for path in target.rglob('*') if path.is_file()}
        row, _ = execute(program, fixtures, 'open-reject', 0, expected_error, directory, case_name)
        row['mutation'] = dict(name=name, file=file, bytes=len(data), sha256=digest(changed),
                               expected_error=expected_error)
        row['unchanged_rejected_files'] = before_files == {
            path.relative_to(target).as_posix(): digest(path) for path in target.rglob('*') if path.is_file()}
        row['passed'] = row['passed'] and row['unchanged_rejected_files']
        rows.append(row)
        if not row['passed']:
            return rows
    return rows


def retain(fixtures, directory):
    records = {}
    for path in sorted(fixtures.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('unexpected link in retained rotation fixture')
        if path.is_file():
            value = path.stat()
            records[path.relative_to(fixtures).as_posix()] = dict(
                bytes=value.st_size, sha256=digest(path), mode=value.st_mode & 0o7777,
                uid=value.st_uid, gid=value.st_gid, links=value.st_nlink)
    archive = directory / 'native-fixtures.tar.gz'
    with tarfile.open(archive, 'w:gz') as stream:
        stream.add(fixtures, arcname='fixtures')
    with tarfile.open(archive, 'r:gz') as stream:
        actual = {}
        for member in stream:
            if member.isfile():
                actual[member.name.removeprefix('fixtures/')] = dict(
                    bytes=member.size,
                    sha256=hashlib.file_digest(stream.extractfile(member), 'sha256').hexdigest(),
                    mode=member.mode, uid=member.uid, gid=member.gid, links=1)
    if actual != records:
        raise RuntimeError('retained fixture does not reproduce native bytes and metadata')
    (directory / 'native-fixtures.json').write_text(json.dumps(records, indent=2) + '\n')
    return dict(path=archive.name, bytes=archive.stat().st_size, sha256=digest(archive),
                verified_files=len(records))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() or os.getegid() or not args.fixtures.is_absolute() or args.fixtures.exists():
        raise RuntimeError('rotation controls require root and a fresh isolated Linux fixture directory')
    args.directory.mkdir(parents=True, exist_ok=False)
    args.fixtures.mkdir(mode=0o755)
    args.fixtures.chmod(0o755)
    source = {name: digest(ROOT / name) for name in INPUTS}
    (args.directory / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    for name in INPUTS:
        output = args.directory / 'source' / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes((ROOT / name).read_bytes())
    program = args.directory / 'account-logbook-rotation'
    command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-DACCOUNT_LOGIN_JOURNAL_LIMIT=3712', '-DACCOUNT_LOGIN_LIVE_LIMIT=4',
               *(str(ROOT / name) for name in SOURCES if name.endswith('.c')),
               str(ROOT / CLIENT), '-Wl,--wrap=write,--wrap=pwrite,--wrap=fsync,--wrap=renameat,--wrap=unlinkat',
               '-o', str(program)]
    with (args.directory / 'build.log').open('wb') as output:
        compiled = subprocess.run(command, env=environment(), stdout=output, stderr=subprocess.STDOUT)
    if compiled.returncode:
        raise RuntimeError('native rotation build failed; build log and captured source retained')
    holder_program = args.directory / 'account-logbook-rotation-holders'
    holder_command = [*command[:command.index(str(ROOT / CLIENT))], str(ROOT / HOLDERS),
                      '-o', str(holder_program)]
    with (args.directory / 'holder-build.log').open('wb') as output:
        compiled = subprocess.run(holder_command, env=environment(), stdout=output, stderr=subprocess.STDOUT)
    if compiled.returncode:
        raise RuntimeError('native shared-holder build failed; captured inputs retained')
    link_inputs = {}
    for name in ('libc.so.6', 'libc.a', 'libc_nonshared.a', 'crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o',
                 'libgcc.a', 'crtbegin.o', 'crtend.o', 'ld-linux-x86-64.so.2'):
        path = Path(subprocess.check_output(['gcc', '-print-file-name=' + name],
                                            text=True, env=environment()).strip()).resolve()
        if not path.is_file():
            raise RuntimeError('missing native rotation linker input: ' + name)
        link_inputs[name] = dict(path=str(path), sha256=digest(path))
    inputs = dict(command=command, binary_sha256=digest(program), build_log_sha256=digest(args.directory / 'build.log'),
                  compiler=subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0],
                  kernel=subprocess.check_output(['uname', '-r'], text=True).strip(),
                  headers=subprocess.check_output(['readelf', '-W', '-l', str(program)], text=True),
                  dynamic=subprocess.check_output(['readelf', '-W', '-d', str(program)], text=True),
                  test_frame_limit=8, test_journal_limit=3712, production_journal_limit=32 * 1024 * 1024,
                  production_live_limit=1024, closed_archive_limit=4, native_link_inputs=link_inputs,
                  holder_command=holder_command, holder_binary_sha256=digest(holder_program),
                  holder_build_log_sha256=digest(args.directory / 'holder-build.log'))
    (args.directory / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    rows = []
    error = None
    phases = {}
    write_phases = {}
    try:
        for scenario in ('basic', 'expiry'):
            row, text = execute(program, args.fixtures, scenario, 0, 0, args.directory)
            rows.append(row)
            if not row['passed']:
                raise RuntimeError('native baseline rotation failed: ' + scenario)
            matches = re.findall(r'^ACCOUNT_ROTATION_PHASES (\d+)$', text, re.MULTILINE)
            if len(matches) != 1 or not 20 <= int(matches[0]) <= 1024:
                raise RuntimeError('missing or unbounded actual publication operation count')
            phases[scenario] = int(matches[0])
            boundaries = re.findall(r'^ACCOUNT_ROTATION_BOUNDARY phase=(\d+) operation=(\w+)$',
                                    text, re.MULTILINE)
            if [int(item[0]) for item in boundaries] != list(range(1, phases[scenario] + 1)) or \
                    any(item[1] not in ('write', 'pwrite', 'fsync', 'renameat', 'unlinkat') for item in boundaries):
                raise RuntimeError('incomplete actual publication operation trace')
            write_phases[scenario] = [int(item[0]) for item in boundaries if item[1] in ('write', 'pwrite')]
            for mode in (1, 2, 3, 4):
                for phase in range(1, phases[scenario] + 1):
                    row, _ = execute(program, args.fixtures, scenario, mode, phase, args.directory)
                    rows.append(row)
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError(f'rotation {scenario} mode={mode} phase={phase} failed')
                print(f'ACCOUNT_ROTATION_NATIVE_FAULT_PASS scenario={scenario} mode={mode} phases={phases[scenario]}', flush=True)
            for mode in (5, 6, 7):
                for phase in write_phases[scenario]:
                    row, _ = execute(program, args.fixtures, scenario, mode, phase, args.directory)
                    rows.append(row)
                    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                    if not row['passed']:
                        raise RuntimeError(f'rotation {scenario} partial mode={mode} phase={phase} failed')
                print(f'ACCOUNT_ROTATION_NATIVE_PARTIAL_PASS scenario={scenario} mode={mode} phases={len(write_phases[scenario])}', flush=True)
        for scenario in ('cyclic', 'metadata', 'live-limit'):
            row, _ = execute(program, args.fixtures, scenario, 0, 0, args.directory)
            rows.append(row)
            if not row['passed']:
                raise RuntimeError('native rotation scenario failed: ' + scenario)
        row, _ = execute_command([str(holder_program), str(args.fixtures / 'holders')],
                                 args.directory / 'holders.log',
                                 'ACCOUNT_ROTATION_HOLDERS_PASS generations=4 leases=2 recovered=2 global_events=24')
        rows.append(row)
        if not row['passed']:
            raise RuntimeError('native rotated shared-holder lifetime failed')
        negatives = metadata_negatives(program, args.fixtures, args.directory)
        rows.extend(negatives)
        if not all(row['passed'] for row in negatives):
            raise RuntimeError('checksum-valid metadata or archive EOF damage accepted')
    except Exception as exception:
        error = str(exception)
    retained = retain(args.fixtures, args.directory)
    unchanged = source == {name: digest(ROOT / name) for name in source}
    libraries_unchanged = all(Path(value['path']).is_file() and
                              digest(Path(value['path'])) == value['sha256']
                              for value in link_inputs.values())
    receipt = dict(passed=error is None and unchanged and libraries_unchanged and all(row['passed'] for row in rows),
                   scenarios=len(rows), publication_phases=phases, write_phases=write_phases,
                   source_unchanged=unchanged, native_link_inputs_unchanged=libraries_unchanged,
                   error=error, native_retention=retained, binary_sha256=digest(program),
                   source_inputs_sha256=digest(args.directory / 'source-inputs.json'))
    (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    (args.directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if not receipt['passed']:
        raise RuntimeError(error or 'rotation validation inputs changed')
    print(f'ACCOUNT_ROTATION_NATIVE_PASS scenarios={len(rows)} publication_phases={phases}', flush=True)


if __name__ == '__main__':
    main()

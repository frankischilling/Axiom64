#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check projection bytes, bounded write counts and actual partial/error writes."""
import argparse
import errno
import hashlib
import itertools
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_logbook_test import SOURCES
from account_logbook_rotation_guest import dead_entry, frames, projections
from account_store_test import environment
from build_musl import compiler_args, loader
from fetch import ROOT

CLIENT = 'userspace/tests/security/account-projection.c'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--provider', choices=('native', 'build', 'runtime', 'all'), default='all')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'all'), default='all')
    parser.add_argument('--sanitize', action='store_true')
    args = parser.parse_args()
    if args.sanitize and (args.provider != 'native' or args.linkage != 'dynamic'):
        parser.error('sanitizers select the native dynamic comparison')
    args.directory = args.directory.resolve()
    if not args.directory.is_relative_to((ROOT / 'build').resolve()):
        raise ValueError('choose a new owned build directory')
    args.directory.mkdir(parents=True, exist_ok=False)
    providers = ('native', 'build', 'runtime') if args.provider == 'all' else (args.provider,)
    linkages = ('static', 'dynamic') if args.linkage == 'all' else (args.linkage,)
    rows = []
    for provider, linkage in itertools.product(providers, linkages):
        folder = args.directory / (provider + '-' + linkage)
        folder.mkdir()
        program = folder / 'projection'
        compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
        command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                   '-I', str(ROOT / 'userspace/accounts'),
                   *(str(ROOT / name) for name in SOURCES if name.endswith('.c')),
                   str(ROOT / CLIENT), '-Wl,--wrap=write', '-o', str(program),
                   *(['-static'] if linkage == 'static' else []),
                   *(['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
                     if args.sanitize else [])]
        subprocess.run(command, cwd=ROOT, env=environment(), check=True)
        run = ([str(loader(provider))] if provider != 'native' and linkage == 'dynamic' else [])
        run += [str(program), str(folder)]
        result = subprocess.run(run, cwd=ROOT, env=environment(), capture_output=True,
                                text=True, timeout=30)
        (folder / 'run.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        raw = (folder / 'frames.bin').read_bytes()
        if raw != (folder / 'frames-after.bin').read_bytes():
            raise AssertionError('projection changed authoritative frames')
        records = frames(raw)
        assert [frame['kind'] for frame in records] == [1, 3, 5, 2] * 32
        ended = records[3::4]
        assert len({frame['terminal'] for frame in ended}) == 32
        expected = projections(dict(generation=1, carried=0, previous_events=0), records)
        expected['utmp'] = b''.join(dead_entry(frame) for frame in ended)
        matches = re.findall(r'^ACCOUNT_PROJECTION kind=(\d+) mode=(\d+) result=(-?\d+) '
                             r'errno=(\d+) bytes=(\d+) calls=(\d+)$', result.stdout, re.M)
        if len(matches) != 16 or {(int(row[0]), int(row[1])) for row in matches} != set(itertools.product(range(4), repeat=2)):
            raise AssertionError('projection case matrix is incomplete')
        for kind, mode, status, error, size, calls in (map(int, match) for match in matches):
            name = ('utmp', 'wtmp', 'btmp', 'auth.log')[kind]
            data = (folder / f'projection-{kind}-{mode}.bin').read_bytes()
            assert len(data) == size
            if mode in (0, 1):
                assert status == 0 and data == expected[name], (provider, linkage, kind, mode)
                if mode == 0:
                    assert calls <= (len(data) + 4095) // 4096, 'small projection writes amplify journal transactions'
                else:
                    assert calls > 1, 'actual interrupted/short writes did not execute'
            else:
                assert status == -1 and error == errno.EIO
                assert expected[name].startswith(data) and len(data) < len(expected[name])
                assert mode != 3 or not data
        rows.append(dict(provider=provider, linkage=linkage, passed=True, cases=16,
                         command=command, run=run,
                         binary_sha256=hashlib.sha256(program.read_bytes()).hexdigest(),
                         frames_sha256=hashlib.sha256(raw).hexdigest()))
        (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        print('ACCOUNT_PROJECTION_WRITE_PASS ' + provider + '-' + linkage + ' cases=16', flush=True)
    (args.directory / 'receipt.json').write_text(json.dumps(dict(passed=True, profiles=len(rows),
                                                              cases=len(rows) * 16), indent=2) + '\n')


if __name__ == '__main__':
    main()

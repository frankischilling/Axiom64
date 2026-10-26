#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe actual kernel thread retirement after all six native pthread joins."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import time
from account_store_test import digest, environment
from build_musl import compiler_args, loader
from fetch import ROOT

SOURCES = ('userspace/tests/process/proc_retirement.c', 'userspace/tests/process/proc.c',
           'userspace/accounts/busy.c', 'userspace/accounts/busy.h', 'scripts/proc_retirement_test.py',
           'scripts/proc_test.py', 'scripts/account_store_test.py', 'scripts/build_musl.py',
           'sources.lock.json', 'Makefile')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/proc-retirement-native')
    args = parser.parse_args()
    if os.geteuid() or os.getegid():
        raise RuntimeError('native credential retirement requires root')
    limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if limit[1] != resource.RLIM_INFINITY and limit[1] < 4160:
        raise RuntimeError('native retirement fixture needs 4160 available descriptors')
    child_limit = (resource.RLIM_INFINITY if limit[0] == resource.RLIM_INFINITY else max(limit[0], 4160), limit[1])
    args.directory.mkdir(parents=True, exist_ok=False)
    sources = {name: digest(ROOT / name) for name in SOURCES}
    (args.directory / 'source-inputs.json').write_text(json.dumps(sources, indent=2) + '\n')
    rows = []
    for provider in ('build', 'runtime', 'native'):
        for linkage in ('static', 'dynamic'):
            case = args.directory / (provider + '-' + linkage)
            case.mkdir()
            program = case / 'program'
            compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
            notice = (Path('/usr/share/doc/libc6/copyright') if provider == 'native' else
                      loader(provider).resolve().parents[2] / 'COPYRIGHT')
            shutil.copy2(notice, case / 'COPYRIGHT')
            command = [*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
                       *(['-static'] if linkage == 'static' else []), str(ROOT / SOURCES[0]),
                       str(ROOT / 'userspace/accounts/busy.c'), '-o', str(program)]
            subprocess.run(command, cwd=ROOT, env=environment(), check=True)
            execute = [str(program)]
            interpreter = None
            if linkage == 'dynamic':
                interpreter = Path('/lib64/ld-linux-x86-64.so.2') if provider == 'native' else loader(provider)
                shutil.copy2(interpreter, case / 'loader')
                execute.insert(0, str(case / 'loader'))
            execute = ['unshare', '--mount', '--pid', '--fork', '--mount-proc', *execute]
            started = time.monotonic_ns()
            with (case / 'native.log').open('xb') as output:
                result = subprocess.run(execute, cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=90,
                                        preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, child_limit))
            text = (case / 'native.log').read_text()
            match = re.fullmatch(r'PROC_RETIREMENT_PASS cycles=64 waited=(\d+) polls=(\d+)\n', text)
            passed = result.returncode == 0 and match is not None and 0 < int(match[1]) <= 64 and int(match[2]) >= int(match[1])
            row = dict(provider=provider, linkage=linkage, command=command, execute=execute,
                       program_sha256=digest(program), loader_sha256=digest(interpreter) if interpreter else None,
                       runtime_notice_sha256=digest(case / 'COPYRIGHT'),
                       log_sha256=digest(case / 'native.log'), returncode=result.returncode,
                       elapsed_ns=time.monotonic_ns() - started, original_descriptor_limit=limit,
                       descriptor_limit=child_limit,
                       original_deadline_seconds=90, passed=passed)
            rows.append(row)
            (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not passed:
                raise RuntimeError('native kernel retirement did not qualify: ' + case.name)
            if provider == 'native' and linkage == 'dynamic':
                with (case / 'held.log').open('xb') as output:
                    held = subprocess.run([*execute, '--held'], cwd=ROOT, env=environment(),
                        stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=90,
                        preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, child_limit))
                failed = (case / 'held.log').read_text()
                row['held_task_rejected'] = held.returncode == 1 and 'PROC_FAIL' in failed and 'elapsed >= 0 && elapsed < 1000000000LL' in failed
                row['held_log_sha256'] = digest(case / 'held.log')
                if not row['held_task_rejected']:
                    raise RuntimeError('a live thread passed the retirement barrier')
                (args.directory / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            print(json.dumps({name: value for name, value in row.items() if name not in ('command','execute')}), flush=True)
    if sources != {name: digest(ROOT / name) for name in sources}:
        raise RuntimeError('native retirement inputs changed')
    print('PROC_RETIREMENT_MATRIX_PASS profiles=6 cycles=384 live_task_rejected=1')


if __name__ == '__main__':
    main()

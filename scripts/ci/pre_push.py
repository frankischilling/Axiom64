#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# @file    scripts/ci/pre_push.py
# @brief   Check the committed source files in a Git push.
# @author  frankischilling
# @date    2026-11-20
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.
"""Validate pushed Git trees within the local push budget."""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib

BUDGET = 9.0
STOP = time.monotonic() + BUDGET
CXX = {'.cc', '.cpp', '.cxx'}
HEADER = {'.h', '.hh', '.hpp', '.hxx'}
NATIVE = CXX | {'.c', '.S', '.s', '.asm', '.ld'}
NEGATIVE = 'userspace/tests/toolchain/broken.c'
VFS_MUSL = 'userspace/tests/fs/vfs.c'
INCLUDE = re.compile(r'(?:#|%:|\?\?=)\s*include(?:_next)?\b([^\n]*)|%include\b([^\n]*)')
HOOK = """#!/bin/sh
# Axiom64 pre-push
case "$(uname -s)" in
    MINGW*|MSYS*) python=python ;;
    *) python=python3 ;;
esac
exec "$python" -B "$(dirname "$0")/axiom64-pre-push.py" "$@"
"""


def run(command, *, cwd=None, stdout=subprocess.PIPE, check=True):
    seconds = STOP - time.monotonic()
    if seconds <= 0:
        raise subprocess.TimeoutExpired(command, BUDGET)
    result = subprocess.run(command, cwd=cwd, stdout=stdout, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, timeout=seconds,
                            env=dict(os.environ, LC_ALL='C'))
    if check and result.returncode:
        detail = (result.stdout or b'') + result.stderr
        raise RuntimeError(detail.decode(errors='replace').strip() or shlex.join(command))
    return result


def git(*args, check=True):
    return run(['git', *args], check=check)


def install():
    hook = Path(os.fsdecode(git('rev-parse', '--path-format=absolute', '--git-path',
                                'hooks/pre-push').stdout.rstrip(b'\r\n')))
    hook.parent.mkdir(parents=True, exist_ok=True)
    if hook.exists() and hook.read_bytes() != HOOK.encode():
        raise RuntimeError(f'{hook} already exists. Keep that hook and call this checker from it.')
    with tempfile.TemporaryDirectory(dir=hook.parent) as temporary:
        stage = Path(temporary)
        program = stage / 'axiom64-pre-push.py'
        shutil.copyfile(Path(__file__), program)
        program.replace(hook.with_name(program.name))
        wrapper = stage / 'pre-push'
        wrapper.write_bytes(HOOK.encode())
        wrapper.chmod(0o755)
        wrapper.replace(hook)
    print(f'Installed {hook}')


def changed_trees(remote):
    trees = {}
    for row in sys.stdin:
        _, head, _, previous = row.split()
        if not int(head, 16):
            continue
        commit = git('rev-parse', '--verify', f'{head}^{{commit}}').stdout.decode().strip()
        if not int(previous, 16):
            upstream = f'refs/remotes/{remote}'
            branch = git('rev-parse', '--verify', upstream + '/HEAD', check=False)
            if branch.returncode:
                branch = git('rev-parse', '--verify', upstream + '/main')
            previous = git('merge-base', branch.stdout.decode().strip(), commit).stdout.decode().strip()
        git(f'--attr-source={commit}', 'diff', '--check', previous, commit, '--')
        changes = git('diff', '--name-only', '-z', '--no-renames', previous, commit, '--').stdout
        trees.setdefault(commit, set()).update(os.fsdecode(path) for path in changes.split(b'\0') if path)
    return trees


def project_source(path):
    return path.startswith(('kernel/', 'userspace/', 'scripts/tests/'))


def suffix(path):
    return Path(path).suffix


def native_command(path, flags):
    if path.startswith('kernel/') and not path.startswith('kernel/tests/') and suffix(path) in CXX:
        return ['g++', *flags, '-fsyntax-only', path]
    warnings = ['-O2', '-Wall', '-Wextra', '-Werror']
    if suffix(path) in CXX:
        return ['g++', '-std=c++20', *warnings, '-Ikernel/include', '-Iuserspace', '-Ivendor',
                '-fsyntax-only', path]
    if suffix(path) == '.c':
        compiler = 'musl-gcc' if path == VFS_MUSL else 'gcc'
        return [compiler, '-std=c11', *warnings, '-I.', '-Iuserspace', '-Iuserspace/tests/net',
                '-Ivendor', '-fsyntax-only', path]
    if suffix(path) == '.asm':
        return ['nasm', '-f', 'elf64', '-o', os.devnull, path]
    return ['gcc', '-c', '-o', os.devnull, path]


def syntax(root, path, flags, linker_fixture):
    if suffix(path) == '.ld':
        run(['ld', '-r', '-T', path, '-o', os.devnull, linker_fixture], cwd=root)
    elif path == NEGATIVE:
        command = native_command(path, flags)
        command.insert(1, '-fmax-errors=1')
        result = run(command, cwd=root, check=False)
        errors = [line for line in result.stderr.decode(errors='replace').splitlines() if 'error:' in line]
        if result.returncode != 1 or len(errors) != 1 or not all(
                token in errors[0] for token in ('missing_symbol', 'implicit-function-declaration')):
            raise RuntimeError(f'{path} must fail with the expected missing symbol diagnostic')
    else:
        run(native_command(path, flags), cwd=root)


def affected_units(root, changed):
    if not any(suffix(path) in NATIVE | HEADER | {'.inc'} for path in changed):
        return []
    units, dependents = set(), {}
    computed_include = False
    for directory in ('kernel', 'userspace', 'scripts/tests', 'vendor'):
        for source in (root / directory).rglob('*'):
            if not source.is_file() or source.suffix not in NATIVE | HEADER | {'.inc'}:
                continue
            path = source.relative_to(root).as_posix()
            if project_source(path) and source.suffix in NATIVE:
                units.add(path)
            text = source.read_text(errors='replace').replace('\\\n', '')
            text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
            for directive in INCLUDE.finditer(text):
                operand = directive.group(1) or directive.group(2) or ''
                literal = re.match(r'\s*[<"]([^">\n]+)[>"]', operand)
                if literal:
                    # Include search paths can vary by recipe. A basename also
                    # selects every candidate when two directories share a name.
                    dependents.setdefault(Path(literal[1]).name, set()).add(path)
                else:
                    computed_include = True
    if computed_include:
        return sorted(units)
    affected = set(changed)
    pending = [Path(path).name for path in changed if suffix(path) in NATIVE | HEADER | {'.inc'}]
    while pending:
        name = pending.pop()
        for dependent in dependents.get(name, ()):
            if dependent not in affected:
                affected.add(dependent)
                pending.append(Path(dependent).name)
    return sorted(units & affected)


def check_snapshot(root, changed):
    present = sorted(path for path in changed if (root / path).is_file() and not (root / path).is_symlink())
    commands = []
    c_family = CXX | HEADER | {'.c'}
    if '.clang-format' in changed or any(suffix(path) in c_family for path in present):
        formatter = shlex.split(run(['make', '-n', 'check-format'], cwd=root).stdout.decode())
        if formatter[1:3] != ['--dry-run', '--Werror']:
            raise RuntimeError('Could not read the project formatter command')
        selected = [path for path in formatter[3:] if path in changed or '.clang-format' in changed]
        missing = [path for path in present if project_source(path) and
                   suffix(path) in c_family and path not in formatter[3:] and
                   not path.startswith('scripts/tests/fixtures/')]
        selected.extend(missing)
        if selected:
            commands.append([*formatter[:3], *selected])
    units = affected_units(root, changed)
    flags = []
    if units or 'Makefile' in changed:
        probe = ['make', '-n', '--eval=pre-push-flags: ; @echo $(CXXFLAGS)', 'pre-push-flags']
        flags = shlex.split(run(probe, cwd=root).stdout.decode())[1:]
        if not flags:
            raise RuntimeError('Could not read the kernel compiler flags')
    linker_fixture = None
    if any(suffix(path) == '.ld' for path in units):
        (root / 'pre-push-empty.s').write_text('.text\n')
        linker_fixture = 'pre-push-empty.o'
        run(['gcc', '-c', 'pre-push-empty.s', '-o', linker_fixture], cwd=root)
    for path in present:
        if suffix(path) == '.sh':
            commands.append(['shellcheck', '--severity=error', '--', path])
        elif suffix(path) == '.py':
            compile((root / path).read_bytes(), path, 'exec')
        elif suffix(path) == '.json':
            json.loads((root / path).read_bytes())
        elif suffix(path) == '.toml':
            tomllib.loads((root / path).read_text())
    workers = len(os.sched_getaffinity(0))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        checks = [pool.submit(run, command, cwd=root) for command in commands]
        checks.extend(pool.submit(syntax, root, path, flags, linker_fixture) for path in units)
        for check in checks:
            check.result()


def check_archive(archive, paths):
    with tempfile.TemporaryDirectory(prefix='axiom64-pre-push-') as temporary:
        root = Path(temporary)
        run(['tar', '-xf', str(archive), '-C', str(root)])
        check_snapshot(root, set(json.loads(Path(paths).read_text(encoding='utf-8'))))


def check_push(remote):
    for commit, changed in changed_trees(remote).items():
        if not changed:
            continue
        with tempfile.TemporaryDirectory(prefix='axiom64-push-inputs-') as temporary:
            stage = Path(temporary)
            archive = stage / 'commit.tar'
            paths = stage / 'changed.json'
            with archive.open('wb') as stream:
                run(['git', 'archive', '--format=tar', commit], stdout=stream)
            paths.write_text(json.dumps(sorted(changed)), encoding='utf-8')
            if os.name == 'nt':
                command = ('set -e; program=$(wslpath -a "$1"); stage=$(wslpath -a "$2"); '
                           'exec python3 -B "$program" --check "$stage/commit.tar" "$stage/changed.json"')
                run(['wsl.exe', '--exec', 'sh', '-c', command, 'pre-push',
                     str(Path(__file__).resolve()), str(stage)])
            else:
                check_archive(archive, paths)


def main():
    try:
        if sys.argv[1:] == ['--install']:
            install()
        elif len(sys.argv) == 4 and sys.argv[1] == '--check':
            check_archive(*sys.argv[2:])
        elif len(sys.argv) == 3:
            check_push(sys.argv[1])
            print(f'Pre-push checks passed in {BUDGET - (STOP - time.monotonic()):.2f}s')
        else:
            raise ValueError('Install with python3 scripts/ci/pre_push.py --install')
    except subprocess.TimeoutExpired:
        print('Pre-push checks exceeded 9 seconds', file=sys.stderr)
        return 1
    except (OSError, RuntimeError, SyntaxError, ValueError) as error:
        detail = str(error).removeprefix('Pre-push checks failed: ')
        print(f'Pre-push checks failed: {detail}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

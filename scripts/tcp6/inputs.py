# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain complete public source and exact executables before IPv6 TCP runs."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile
from fetch import ROOT
from build_musl import loader
from compile_uapi_client import audit_compile, sources


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def source_names():
    marker = ROOT / '.git'
    if marker.exists() or marker.is_symlink():
        # A checkout keeps exact index/untracked semantics. A broken Git setup
        # must fail instead of silently switching its source boundary.
        names = subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT),
                                         'ls-files', '--cached', '--others',
                                         '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
        return sorted({name for name in names if name and (ROOT / name).is_file()}), 'git'
    # Hosted test jobs restore the public source and build archive without .git.
    # Enumerate only publication roots, never build/download/private directories.
    files = {'.clang-format', '.gitattributes', '.gitignore', 'README.md', 'LICENSE',
             'Makefile', 'sources.lock.json', 'ports.lock.json', 'dependencies.json'}
    folders = {'.github', 'kernel', 'userspace', 'boot', 'vendor', 'docs', 'scripts'}
    if not (ROOT / 'Makefile').is_file():
        raise ValueError('exported TCP6 source root lacks its Makefile')
    paths = [ROOT / name for name in files if (ROOT / name).is_file()]
    paths.extend(path for folder in folders for path in (ROOT / folder).rglob('*')
                 if path.is_file() and not set(path.relative_to(ROOT).parts) &
                 {'.git', '.local', '__pycache__'} and path.suffix != '.pyc')
    names, root = [], ROOT.resolve()
    for path in paths:
        actual = path.resolve()
        if not actual.is_relative_to(root) or actual.relative_to(root).parts[0] not in files | folders:
            raise ValueError('exported TCP6 source link escapes public inputs')
        names.append(path.relative_to(ROOT).as_posix())
    return sorted(set(names)), 'exported-public-roots'


def freeze(directory):
    names, enumeration = source_names()
    records = {name: digest(ROOT / name) for name in names}
    with zipfile.ZipFile(directory / 'source.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.write(ROOT / name, name)
    if records != {name: digest(ROOT / name) for name in names}:
        raise ValueError('TCP6 source changed during its snapshot')
    write(directory / 'source-inputs.json', records)
    return dict(source_zip_sha256=digest(directory / 'source.zip'),
                source_inputs_sha256=digest(directory / 'source-inputs.json'), files=len(records),
                enumeration=enumeration)


def program(directory, profile, suite='loss'):
    from tcp6.profiles import definition
    config = definition(suite)
    binary = ROOT / 'build' / (config['program'] + '-' + profile)
    manifest = binary.with_suffix('.inputs.json')
    if profile == 'native':
        command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                   *config['flags'], config['source'], '-o', str(binary)]
        before = sources(command, ROOT)
        subprocess.run(command, cwd=ROOT, check=True)
        if before != sources(command, ROOT):
            raise ValueError('native TCP6 sources changed while compiling')
        write(manifest, dict(command=command, sources=before, product=dict(
            bytes=binary.stat().st_size, sha256=digest(binary)),
            compiler_version=subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0]))
    compiled = audit_compile(binary, ROOT)
    shutil.copy2(binary, directory / 'program')
    shutil.copy2(manifest, directory / 'program.inputs.json')
    products = {'program': digest(directory / 'program'),
                'program.inputs.json': digest(directory / 'program.inputs.json')}
    if profile == 'dynamic':
        shutil.copy2(loader('build'), directory / 'loader')
        products['loader'] = digest(directory / 'loader')
    write(directory / 'products.json', products)
    return compiled

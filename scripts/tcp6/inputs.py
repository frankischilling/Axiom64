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


def freeze(directory):
    names = subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT),
                                     'ls-files', '--cached', '--others',
                                     '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    names = sorted({name for name in names if name and (ROOT / name).is_file()})
    records = {name: digest(ROOT / name) for name in names}
    with zipfile.ZipFile(directory / 'source.zip', 'x', zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.write(ROOT / name, name)
    if records != {name: digest(ROOT / name) for name in names}:
        raise ValueError('TCP6 source changed during its snapshot')
    write(directory / 'source-inputs.json', records)
    return dict(source_zip_sha256=digest(directory / 'source.zip'),
                source_inputs_sha256=digest(directory / 'source-inputs.json'), files=len(records))


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

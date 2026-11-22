#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/build_pam_accounts.py
# @brief   Build the account module against the pinned Linux-PAM ABI.
# @author  frankischilling
# @date    2026-11-22
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

"""Build the Axiom64 account module for the installed display manager."""

import argparse
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

from build_accounts import MODULES, environment
from build_libxcrypt import ensure as password_library
from build_musl import compiler_args
from fetch import ROOT
from ports import LOCKFILE, locked_package
from sources import SOURCE_LOCK, source_file


def stage_pam(directory):
    package = next(p for p in json.loads(LOCKFILE.read_text())['packages']
                   if p['name'] == 'linux-pam')
    recipe = next(p for p in json.loads(SOURCE_LOCK.read_text())['ports']
                  if p['origin'] == package['origin'] and p['commit'] == package['source_commit'])
    source = source_file(recipe['origin'], next(f for f in recipe['files']
                                                if f['name'].startswith('Linux-PAM-')))
    archive = locked_package(package)
    headers = directory / 'security'
    headers.mkdir()
    with tarfile.open(source) as stream:
        for member in stream.getmembers():
            path = Path(member.name)
            if (member.isfile() and path.suffix == '.h' and
                    path.parts[-4:-1] == ('libpam', 'include', 'security')):
                (headers / path.name).write_bytes(stream.extractfile(member).read())
    if not (headers / 'pam_modules.h').is_file():
        raise RuntimeError('Linux-PAM public headers missing from the locked source')
    library = directory / 'libpam.so.0'
    with tarfile.open(archive, 'r:gz', ignore_zeros=True) as stream:
        library.write_bytes(stream.extractfile('usr/lib/libpam.so.0').read())
    return archive, library


def build(output):
    crypt = password_library('build') / 'dynamic/stage/usr'
    accounts = ROOT / 'userspace/accounts'
    with tempfile.TemporaryDirectory(prefix='axiom64-pam-') as temporary:
        stage = Path(temporary)
        stage_pam(stage)
        result = stage / 'pam_axiom64.so'
        subprocess.run([
            *compiler_args('build'), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-fPIC', '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections',
            f'-I{stage}', f'-I{crypt / "include"}', '-shared',
            '-Wl,-z,defs,--gc-sections', f'-ffile-prefix-map={ROOT}=/usr/src/axiom64',
            *(str(accounts / f'{name}.c') for name in (*MODULES, 'logbook_rotation', 'pam')),
            f'-L{stage}', f'-L{crypt / "lib"}', '-l:libpam.so.0', '-lcrypt', '-o', str(result),
        ], check=True, env=environment(), cwd=ROOT)
        tags = subprocess.check_output(['readelf', '-W', '-d', result], text=True)
        if ('libpam.so.0' not in tags or 'libcrypt.so.2' not in tags or
                'RPATH' in tags or 'RUNPATH' in tags):
            raise RuntimeError('account PAM module has unexpected ELF dependencies')
        output.write_bytes(result.read_bytes())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    build(parser.parse_args().output)

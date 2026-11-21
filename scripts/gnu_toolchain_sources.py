#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# @file    scripts/gnu_toolchain_sources.py
# @brief   Authenticate GNU cross-toolchain sources.
# @author  frankischilling
# @date    2026-11-20
#
# Verifies pinned releases, signer certificates and GCC prerequisite archives.
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

import json
from pathlib import Path
import subprocess
import tempfile

from fetch import ROOT
from ports import download
from sources import CACHE, SOURCE_LOCK, verify


ORIGIN = 'gnu-cross-toolchain'
INFRASTRUCTURE = 'https://gcc.gnu.org/pub/gcc/infrastructure/'
KEYS = ROOT / 'vendor/gnu-toolchain/release-keys.asc'


def pins():
    return json.loads(SOURCE_LOCK.read_text())['gnu_cross_toolchain']


def archive_file(name, url, checksum, offline):
    destination = CACHE / ORIGIN / name
    if offline:
        if not destination.is_file():
            raise RuntimeError(f'GNU toolchain source missing from offline cache: {name}')
        return verify(destination, checksum, 'sha256')
    return download(url, destination, expected_sha256=checksum)


def release_inputs(lock, names, offline=False):
    verify(KEYS, lock['keys_sha256'], 'sha256')
    paths = [KEYS]
    signed = []
    with tempfile.TemporaryDirectory(prefix='axiom64-gnu-signatures-') as home:
        keyring = Path(home) / 'release-keys.gpg'
        subprocess.run(['gpg', '--batch', '--homedir', home, '--output', str(keyring),
                        '--dearmor', str(KEYS)], check=True)
        for component in names:
            release = lock['releases'][component]
            name, url = release['archive'], release['url']
            source = archive_file(name, url, release['sha256'], offline)
            signature = archive_file(name + '.sig', url + '.sig', release['signature_sha256'], offline)
            result = subprocess.run(['gpgv', '--homedir', home, '--keyring', str(keyring), '--status-fd',
                                     '1', str(signature), str(source)], text=True, capture_output=True)
            signers = [line.split()[-1] for line in result.stdout.splitlines()
                       if line.startswith('[GNUPG:] VALIDSIG ')]
            if result.returncode or signers != [release['signer']]:
                raise RuntimeError(f'{name}: release signature failed\n{result.stderr}')
            paths.extend((source, signature))
            signed.append({'archive': name, 'signer': signers[0]})
    return paths, signed


def source_inputs(offline=False):
    lock = pins()
    paths, signed = release_inputs(lock, lock['releases'], offline)
    for item in lock['gcc_prerequisites'].values():
        name = item['archive']
        paths.append(archive_file(name, INFRASTRUCTURE + name, item['sha256'], offline))
    return paths, signed

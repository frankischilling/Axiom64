# SPDX-License-Identifier: GPL-3.0-or-later
"""Read completed, fingerprinted OpenSSL products without changing their build."""
import hashlib
import json
import os
from pathlib import Path

from build_musl import ensure as musl
from build_openssl import OUTPUT, digest, native_inputs
from fetch import LOCK, ROOT


def provider(name):
    candidates = []
    for manifest in (OUTPUT / name).glob('*/manifest.json'):
        data = json.loads(manifest.read_text())
        if (data['dependency'] == LOCK['openssl'] and data['provider'] == name and
                data['recipe_sha256'] == digest(ROOT / 'scripts/build_openssl.py')):
            candidates.append((manifest, data))
    if len(candidates) != 1:
        raise RuntimeError('build exactly one current OpenSSL provider first: ' + name)
    manifest, data = candidates[0]
    identity = {key: data[key] for key in ('dependency', 'provider', 'compiler', 'target',
                'libc_identity', 'native_inputs', 'uapi', 'recipe_sha256', 'uapi_recipe_sha256')}
    expected = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    if data['identity'] != expected or manifest.parent.name != expected:
        raise RuntimeError('OpenSSL product identity differs')
    if data['uapi_recipe_sha256'] != digest(ROOT / 'scripts/linux_uapi.py'):
        raise RuntimeError('OpenSSL UAPI recipe changed')
    if name == 'native':
        if data['native_inputs'] != native_inputs():
            raise RuntimeError('native OpenSSL linker inputs changed')
    elif data['libc_identity'] != json.loads((musl(name) / 'manifest.json').read_text())['identity']:
        raise RuntimeError('OpenSSL libc identity differs')
    for path, value in data['products'].items():
        if digest(manifest.parent / path) != value:
            raise RuntimeError('OpenSSL product changed: ' + path)
    for path, value in data['symlinks'].items():
        if os.readlink(manifest.parent / path) != value:
            raise RuntimeError('OpenSSL product link changed: ' + path)
    return manifest.parent, data


def products(directory, linkage):
    stage = directory / linkage / 'stage'
    names = {'usr/bin/openssl': stage / 'usr/bin/openssl',
             'etc/ssl/openssl.cnf': stage / 'etc/ssl/openssl.cnf'}
    if linkage == 'dynamic':
        names.update({'lib/libcrypto.so.3': stage / 'usr/lib/libcrypto.so.3',
                      'lib/libssl.so.3': stage / 'usr/lib/libssl.so.3',
                      'usr/lib/ossl-modules/legacy.so': stage / 'usr/lib/ossl-modules/legacy.so'})
    return names

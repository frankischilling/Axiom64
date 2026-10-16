#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise cache invalidation and archive retention without building OpenSSL."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('crypto_cache', ROOT / 'scripts/ci/crypto_cache.py')
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class CryptoCacheTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='crypto-cache-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in cache.source_inputs(ROOT):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.host = dict(compiler='14.2', target='x86_64-linux-gnu',
                         tools={'gcc': 'actual-tool-digest'}, libraries={'libc.a': 'actual-lib-digest'},
                         headers={'/usr/include/stdio.h': 'actual-header-digest'})

    def key(self, host=None):
        return cache.identity(self.root, self.host if host is None else host)[0]

    def test_lock_recipe_and_patch_changes_invalidate(self):
        before = self.key()
        patch = json.loads((self.root / 'sources.lock.json').read_text())['musl_local_patches'][0]['path']
        for name in ('dependencies.json', 'ports.lock.json', 'sources.lock.json',
                     'scripts/build_openssl.py', 'scripts/build_musl.py',
                     'scripts/linux_uapi.py', patch):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                self.assertNotEqual(before, self.key())
                path.write_bytes(original)

    def test_host_tool_library_and_header_changes_invalidate(self):
        before = self.key()
        for name in self.host:
            with self.subTest(name=name):
                changed = copy.deepcopy(self.host)
                changed[name] = 'changed'
                self.assertNotEqual(before, self.key(changed))

    def test_unrelated_kernel_and_document_changes_reuse(self):
        before = self.key()
        for name in ('kernel/process/task.cpp', 'docs/testing.md'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('unrelated changes\n')
        self.assertEqual(before, self.key())

    def completed_products(self):
        for dependency, providers in (('musl', ('build', 'runtime')),
                                      ('openssl', cache.PROVIDERS)):
            for provider in providers:
                directory = self.root / 'build' / dependency / provider / ('a' * 64)
                names = ['sysroot/usr/lib/libc.a'] if dependency == 'musl' else [
                    'LICENSE.txt', 'AUTHORS.md', 'INSTALL.md',
                    'static/stage/usr/bin/openssl', 'dynamic/stage/usr/lib/libcrypto.so.3',
                    'static/build/include/openssl/configuration.h',
                    'dynamic/build/include/openssl/configuration.h']
                products = {}
                for name in names:
                    product = directory / name
                    product.parent.mkdir(parents=True, exist_ok=True)
                    product.write_bytes((provider + '/' + name).encode())
                    if name.endswith('/bin/openssl'):
                        product.chmod(0o755)
                    products[name] = cache.digest(product)
                links = {}
                if dependency == 'openssl':
                    name = 'dynamic/stage/usr/lib/libcrypto.so'
                    (directory / name).symlink_to('libcrypto.so.3')
                    links[name] = 'libcrypto.so.3'
                    # This real intermediate must never enter the reusable cache.
                    (directory / 'static/build/unused.o').write_bytes(b'intermediate object')
                (directory / 'manifest.json').write_text(json.dumps(dict(
                    identity=directory.name, provider=provider, products=products, symlinks=links)))

    def test_declared_paths_round_trip_all_products_and_links(self):
        self.completed_products()
        original = cache.check_products(self.root)
        modes = {path.relative_to(self.root).as_posix(): path.stat().st_mode & 0o777
                 for path in self.root.rglob('*') if path.is_file() and not path.is_symlink()
                 and cache.covered(path.relative_to(self.root).as_posix(), cache.cache_paths())}
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as stream:
            selected = set()
            for pattern in cache.cache_paths():
                for path in self.root.glob(pattern):
                    if path not in selected:
                        selected.add(path)
                        stream.add(path, arcname=path.relative_to(self.root).as_posix())
        archive.seek(0)
        restored = self.root / 'restored'
        with tarfile.open(fileobj=archive) as stream:
            self.assertFalse(any(name.endswith('unused.o') for name in stream.getnames()))
            stream.extractall(restored, filter='data')
        self.assertEqual(original, cache.check_products(restored))
        self.assertEqual(modes, {name: (restored / name).stat().st_mode & 0o777 for name in modes})

    def test_missing_changed_and_omitted_products_fail(self):
        self.completed_products()
        directory = self.root / 'build/openssl/runtime' / ('a' * 64)
        path = directory / 'static/build/include/openssl/configuration.h'
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            cache.check_products(self.root)
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'product changed'):
            cache.check_products(self.root)
        path.write_bytes(original)
        manifest = directory / 'manifest.json'
        data = json.loads(manifest.read_text())
        data['products']['static/build/unused.o'] = cache.digest(directory / 'static/build/unused.o')
        manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, 'omitted from cache paths'):
            cache.check_products(self.root)

    def test_changed_link_fails(self):
        self.completed_products()
        link = self.root / 'build/openssl/native' / ('a' * 64) / 'dynamic/stage/usr/lib/libcrypto.so'
        link.unlink()
        link.symlink_to('wrong.so')
        with self.assertRaisesRegex(RuntimeError, 'link changed'):
            cache.check_products(self.root)

    def test_incomplete_provider_set_and_wrong_identity_fail(self):
        self.completed_products()
        directory = self.root / 'build/musl/runtime' / ('a' * 64)
        manifest = directory / 'manifest.json'
        original = manifest.read_bytes()
        manifest.unlink()
        with self.assertRaisesRegex(RuntimeError, 'expected one completed musl/runtime'):
            cache.check_products(self.root)
        data = json.loads(original)
        data['identity'] = 'b' * 64
        manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(RuntimeError, 'manifest identity differs'):
            cache.check_products(self.root)


if __name__ == '__main__':
    unittest.main()

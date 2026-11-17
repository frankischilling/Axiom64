#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise cache invalidation and complete library/source retention without rebuilding."""
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
        for name in set(cache.source_inputs(ROOT)) | {'scripts/build_curl.py'}:
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
                     'scripts/build_openssl.py', 'scripts/build_musl.py', 'scripts/build_curl.py',
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
                                      ('openssl', cache.PROVIDERS), ('curl', cache.PROVIDERS)):
            for provider in providers:
                directory = self.root / 'build' / dependency / provider / ('a' * 64)
                names = ['sysroot/usr/lib/libc.a'] if dependency == 'musl' else [
                    'LICENSE.txt', 'AUTHORS.md', 'INSTALL.md',
                    'static/stage/usr/bin/openssl', 'dynamic/stage/usr/lib/libcrypto.so.3',
                    'static/build/include/openssl/configuration.h',
                    'dynamic/build/include/openssl/configuration.h']
                if dependency == 'curl':
                    names = ['COPYING', 'README', 'INSTALL.md', 'release-signature.log',
                             'static/stage/usr/bin/curl', 'dynamic/stage/usr/lib/libcurl.so.4.8.0',
                             'static/metadata-original/usr/bin/curl-config',
                             'dynamic/metadata-original/usr/lib/pkgconfig/libcurl.pc',
                             'static/build/lib/curl_config.h', 'dynamic/build/lib/curl_config.h',
                             'static/build/config.log', 'dynamic/build/config.log']
                products = {}
                for name in names:
                    product = directory / name
                    product.parent.mkdir(parents=True, exist_ok=True)
                    product.write_bytes((provider + '/' + name).encode())
                    if name.endswith(('/bin/openssl', '/bin/curl')):
                        product.chmod(0o755)
                    products[name] = cache.digest(product)
                links = {}
                if dependency in ('openssl', 'curl'):
                    name = 'dynamic/stage/usr/lib/' + ('libcrypto.so' if dependency == 'openssl' else 'libcurl.so')
                    target = 'libcrypto.so.3' if dependency == 'openssl' else 'libcurl.so.4.8.0'
                    (directory / name).symlink_to(target)
                    links[name] = target
                    # This real intermediate must never enter the reusable cache.
                    (directory / 'static/build/unused.o').write_bytes(b'intermediate object')
                sources, source_links = {}, {}
                if dependency == 'curl':
                    for name in ('curl-release/configure', 'curl-release/COPYING', 'curl-release/src/tool_main.c'):
                        source = directory / 'source' / name
                        source.parent.mkdir(parents=True, exist_ok=True)
                        source.write_bytes(('actual source/' + name).encode())
                        sources[name] = cache.digest(source)
                    (directory / 'source/curl-release/LICENSE').symlink_to('COPYING')
                    source_links['curl-release/LICENSE'] = 'COPYING'
                (directory / 'manifest.json').write_text(json.dumps(dict(identity=directory.name,
                    provider=provider, products=products, symlinks=links, source_inputs=sources, source_symlinks=source_links)))

    def test_declared_paths_round_trip_all_products_and_links(self):
        self.completed_products()
        original = cache.check_products(self.root)
        self.assertEqual(len(original), 8)
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

    def test_missing_curl_provider_is_not_a_complete_cache(self):
        self.completed_products()
        (self.root / 'build/curl/native' / ('a' * 64) / 'manifest.json').unlink()
        with self.assertRaisesRegex(RuntimeError, 'expected one completed curl/native'):
            cache.check_products(self.root)

    def test_changed_curl_source_and_source_link_are_rejected(self):
        self.completed_products()
        directory = self.root / 'build/curl/runtime' / ('a' * 64)
        path = directory / 'source/curl-release/src/tool_main.c'
        original = path.read_bytes()
        path.write_bytes(b'changed source')
        with self.assertRaisesRegex(RuntimeError, 'source changed'):
            cache.check_products(self.root)
        path.write_bytes(original)
        path = directory / 'source/curl-release/LICENSE'
        path.unlink()
        path.symlink_to('configure')
        with self.assertRaisesRegex(RuntimeError, 'source link changed'):
            cache.check_products(self.root)

    def test_missing_source_inventory_is_rejected(self):
        self.completed_products()
        path = self.root / 'build/curl/build' / ('a' * 64) / 'manifest.json'
        saved = json.loads(path.read_text())
        saved['source_inputs'] = {}
        path.write_text(json.dumps(saved))
        with self.assertRaisesRegex(RuntimeError, 'expected retained curl source inventory'):
            cache.check_products(self.root)

    def test_source_inventory_cannot_escape_its_retained_root(self):
        self.completed_products()
        directory = self.root / 'build/curl/build' / ('a' * 64)
        outside = directory / 'outside-source.c'
        outside.write_bytes(b'not a retained source member')
        path = directory / 'manifest.json'
        saved = json.loads(path.read_text())
        saved['source_inputs']['../outside-source.c'] = cache.digest(outside)
        path.write_text(json.dumps(saved))
        with self.assertRaisesRegex(RuntimeError, 'source omitted from cache paths'):
            cache.check_products(self.root)

    def test_source_directory_cannot_redirect_outside_the_cache(self):
        self.completed_products()
        external = tempfile.TemporaryDirectory(prefix='crypto-cache-external-')
        self.addCleanup(external.cleanup)
        source = self.root / 'build/curl/build' / ('a' * 64) / 'source'
        destination = Path(external.name) / 'source'
        shutil.move(source, destination)
        source.symlink_to(destination, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'source directory escapes cache root'):
            cache.check_products(self.root)

    def test_cache_paths_are_anchored_and_have_one_component_wildcards(self):
        paths = cache.cache_paths()
        self.assertTrue(cache.covered('build/openssl/native/id/static/stage/usr/lib/libcrypto.a', paths))
        self.assertFalse(cache.covered('unrelated/build/openssl/native/id/static/stage/usr/lib/libcrypto.a', paths))
        self.assertFalse(cache.covered('build/openssl/native/id/static/staged/libcrypto.a', paths))
        self.assertFalse(cache.covered('build/openssl/native/static/stage/usr/lib/libcrypto.a', paths))


if __name__ == '__main__':
    unittest.main()

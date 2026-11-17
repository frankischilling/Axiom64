# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise cache ownership and pinned bytes through owned files and HTTP."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import fcntl
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import ports
from ports import download

BODY=bytes(range(256))*8192


class Downloads(unittest.TestCase):
    def setUp(self):
        self.workspace=tempfile.TemporaryDirectory(prefix='axiom64-download-cache-')
        self.addCleanup(self.workspace.cleanup)
        self.root=Path(self.workspace.name)
        self.body=BODY
        self.release=threading.Event()
        self.first_request=threading.Event()
        self.two_requests=threading.Event()
        self.requests=0
        self.guard=threading.Lock()
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                with owner.guard:
                    owner.requests+=1
                    if owner.requests>=2:
                        owner.two_requests.set()
                    owner.first_request.set()
                if self.path.endswith('/unavailable'):
                    self.send_response(404)
                    self.send_header('Content-Length','0')
                    self.end_headers()
                    return
                body=owner.body
                self.send_response(200)
                self.send_header('Content-Length',str(len(body)))
                self.end_headers()
                if owner.release.wait(5):
                    self.wfile.write(body)
            def log_message(self,*args):
                pass
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.server.daemon_threads=True
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.url=f'http://127.0.0.1:{self.server.server_port}/package'

    def close_server(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.assertFalse(self.thread.is_alive())

    def test_simultaneous_same_destination_publishes_once_and_both_callers_complete(self):
        target=self.root/'same.apk'
        start=threading.Barrier(3)
        def one():
            start.wait(timeout=2)
            return download(self.url,target)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(one) for _ in range(2)]
            try:
                start.wait(timeout=2)
                # With the old implementation both actual writers open one
                # inode before either response body arrives. This makes its
                # missing-.part failure deterministic. A serialized download
                # has only one HTTP request and one open output descriptor.
                deadline=time.monotonic()+.5
                while time.monotonic()<deadline:
                    opened=0
                    for descriptor in Path('/proc/self/fd').iterdir():
                        try:
                            opened+=descriptor.resolve()==target.with_suffix('.apk.part')
                        except OSError:
                            pass
                    if opened>=2:
                        break
                    time.sleep(.001)
            finally:
                self.release.set()
            self.assertEqual([future.result(timeout=5) for future in futures],[target,target])
        self.assertEqual(target.read_bytes(),BODY)
        self.assertEqual(self.requests,1)
        self.assertFalse(target.with_suffix('.apk.part').exists())
        self.assertEqual(download(self.url,target),target)
        self.assertEqual(self.requests,1)

    def test_distinct_destinations_still_download_concurrently(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(download,self.url+'/'+str(index),self.root/f'{index}.apk') for index in range(2)]
            try:
                concurrent=self.two_requests.wait(2)
            finally:
                self.release.set()
            paths=[future.result(timeout=5) for future in futures]
        self.assertTrue(concurrent)
        self.assertEqual(self.requests,2)
        self.assertTrue(all(path.read_bytes()==BODY for path in paths))

    def test_failed_transfer_keeps_destination_unpublished_and_releases_ownership(self):
        class Interrupted(io.BytesIO):
            def read(self,size=-1):
                if self.tell():
                    raise OSError('controlled interrupted body')
                return super().read(1024)
        target=self.root/'interrupted.apk'
        with patch('ports.urllib.request.urlopen',return_value=Interrupted(BODY)):
            with self.assertRaisesRegex(OSError,'controlled interrupted body'):
                download(self.url,target)
        self.assertFalse(target.exists())
        self.assertEqual(target.with_suffix('.apk.part').read_bytes(),BODY[:1024])
        self.release.set()
        self.assertEqual(download(self.url,target),target)
        self.assertEqual(target.read_bytes(),BODY)

    def package(self,*,vendored=False):
        package=dict(name='package',archive='package.apk',url=self.url,
                     sha256=hashlib.sha256(BODY).hexdigest())
        if vendored:
            package['url']=self.url+'/unavailable'
            package['vendored_archive']='vendor/ports/package.apk'
            source=self.root/package['vendored_archive']
            source.parent.mkdir(parents=True,exist_ok=True)
            source.write_bytes(BODY)
        return package

    def test_declared_archive_copies_verified_bytes_with_unavailable_origin(self):
        package=self.package(vendored=True)
        target=self.root/'downloads/ports'/package['archive']
        with self.assertRaises(urllib.error.HTTPError) as failure:
            urllib.request.urlopen(package['url'],timeout=2)
        self.assertEqual(failure.exception.code,404)
        self.assertFalse(target.exists())
        with patch.object(ports,'ROOT',self.root):
            self.assertEqual(ports.locked_package(package),target)
            self.assertEqual(target.read_bytes(),BODY)
            with patch('ports.urllib.request.urlopen',side_effect=AssertionError('warm cache fetched')):
                self.assertEqual(ports.locked_package(package),target)
        self.assertEqual(self.requests,1)
        self.assertFalse(target.with_suffix('.apk.part').exists())

    def test_declared_source_is_verified_even_with_warm_cache(self):
        package=self.package(vendored=True)
        source=self.root/package['vendored_archive']
        source.write_bytes(b'corrupted preserved archive')
        target=self.root/'downloads/ports'/package['archive']
        target.parent.mkdir(parents=True)
        for warm in (False,True):
            with self.subTest(warm=warm):
                if warm:
                    target.write_bytes(BODY)
                with patch.object(ports,'ROOT',self.root), patch('ports.urllib.request.urlopen',side_effect=AssertionError('invalid source fetched')):
                    with self.assertRaisesRegex(RuntimeError,'SHA-256 mismatch'):
                        ports.locked_package(package)
                self.assertEqual(target.exists(),warm)
                if warm:
                    self.assertEqual(target.read_bytes(),BODY)
                self.assertFalse(target.with_suffix('.apk.part').exists())
        self.assertEqual(self.requests,0)

    def test_corrupted_cached_bytes_are_rejected_without_replacement(self):
        target=self.root/'downloads/ports/package.apk'
        target.parent.mkdir(parents=True)
        target.write_bytes(b'corrupted cache')
        for vendored in (False,True):
            with self.subTest(vendored=vendored):
                package=self.package(vendored=vendored)
                with patch.object(ports,'ROOT',self.root), patch('ports.urllib.request.urlopen',side_effect=AssertionError('corrupt cache fetched')):
                    with self.assertRaisesRegex(RuntimeError,'SHA-256 mismatch'):
                        ports.locked_package(package)
                self.assertEqual(target.read_bytes(),b'corrupted cache')
                self.assertFalse(target.with_suffix('.apk.part').exists())
        self.assertEqual(self.requests,0)

    def test_corrupted_http_body_stays_unpublished_and_releases_lock(self):
        package=self.package()
        target=self.root/'downloads/ports'/package['archive']
        self.body=b'corrupted HTTP body'
        self.release.set()
        with patch.object(ports,'ROOT',self.root):
            with self.assertRaisesRegex(RuntimeError,'SHA-256 mismatch'):
                ports.locked_package(package)
            self.assertFalse(target.exists())
            self.assertEqual(target.with_suffix('.apk.part').read_bytes(),self.body)
            self.body=BODY
            self.assertEqual(ports.locked_package(package),target)
        self.assertEqual(target.read_bytes(),BODY)
        self.assertFalse(target.with_suffix('.apk.part').exists())
        self.assertEqual(self.requests,2)

    def test_pinned_concurrent_callers_verify_under_owned_destination_lock(self):
        package=self.package()
        target=self.root/'downloads/ports'/package['archive']
        lock=target.with_suffix('.apk.lock')
        verified=[]
        verify_archive=ports.verify_archive
        start=threading.Barrier(3)
        def verify_owned(path,expected):
            with lock.open('a') as contender:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender,fcntl.LOCK_EX|fcntl.LOCK_NB)
            verify_archive(path,expected)
            verified.append(path)
        def one():
            start.wait(timeout=2)
            return ports.locked_package(package)
        with patch.object(ports,'ROOT',self.root), patch('ports.verify_archive',side_effect=verify_owned):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures=[pool.submit(one) for _ in range(2)]
                try:
                    start.wait(timeout=2)
                    self.assertTrue(self.first_request.wait(2))
                    self.assertFalse(target.exists())
                finally:
                    self.release.set()
                self.assertEqual([future.result(timeout=5) for future in futures],[target,target])
        self.assertEqual(verified,[target.with_suffix('.apk.part'),target])
        self.assertEqual(target.read_bytes(),BODY)
        self.assertEqual(self.requests,1)
        self.assertFalse(target.with_suffix('.apk.part').exists())

    def test_declared_source_changed_during_copy_stays_unpublished(self):
        package=self.package(vendored=True)
        source=self.root/package['vendored_archive']
        target=self.root/'downloads/ports'/package['archive']
        urlopen=urllib.request.urlopen
        def change_before_open(request,**kwargs):
            self.assertEqual(request.full_url,source.as_uri())
            source.write_bytes(b'changed after source verification')
            return urlopen(request,**kwargs)
        with patch.object(ports,'ROOT',self.root), patch('ports.urllib.request.urlopen',side_effect=change_before_open):
            with self.assertRaisesRegex(RuntimeError,'SHA-256 mismatch'):
                ports.locked_package(package)
        self.assertFalse(target.exists())
        self.assertEqual(target.with_suffix('.apk.part').read_bytes(),source.read_bytes())
        self.assertEqual(self.requests,0)

    def test_missing_or_escaping_declarations_fail_even_with_warm_cache(self):
        package=self.package(vendored=True)
        source=self.root/package['vendored_archive']
        target=self.root/'downloads/ports'/package['archive']
        target.parent.mkdir(parents=True)
        target.write_bytes(BODY)
        (source.parent/'directory').mkdir()
        declarations=[None,42,'',str(source),'../package.apk',
                      'vendor/ports/../package.apk','vendor/other/package.apk',
                      'vendor\\ports\\package.apk','vendor/ports',
                      'vendor/ports/missing.apk','vendor/ports/directory']
        for name in declarations:
            with self.subTest(declaration=name):
                invalid=dict(package,vendored_archive=name)
                with patch.object(ports,'ROOT',self.root), patch('ports.urllib.request.urlopen',side_effect=AssertionError('invalid declaration fetched')):
                    with self.assertRaises((RuntimeError,OSError)):
                        ports.locked_package(invalid)
                self.assertEqual(target.read_bytes(),BODY)
        self.assertEqual(self.requests,0)

    def test_symlink_declarations_fail_even_with_warm_cache(self):
        package=self.package(vendored=True)
        source=self.root/package['vendored_archive']
        target=self.root/'downloads/ports'/package['archive']
        target.parent.mkdir(parents=True)
        target.write_bytes(BODY)
        (source.parent/'alias.apk').symlink_to(source)
        (source.parent/'alias-directory').symlink_to(source.parent,target_is_directory=True)
        for name in ('vendor/ports/alias.apk','vendor/ports/alias-directory/package.apk'):
            with self.subTest(declaration=name):
                invalid=dict(package,vendored_archive=name)
                with patch.object(ports,'ROOT',self.root), patch('ports.urllib.request.urlopen',side_effect=AssertionError('symlink source fetched')):
                    with self.assertRaisesRegex(RuntimeError,'without aliases'):
                        ports.locked_package(invalid)
                self.assertEqual(target.read_bytes(),BODY)
        self.assertEqual(self.requests,0)

    def test_package_iterator_uses_declared_archives_offline(self):
        package=self.package(vendored=True)
        lockfile=self.root/'ports.lock.json'
        lockfile.write_text(json.dumps(dict(packages=[package])))
        target=self.root/'downloads/ports'/package['archive']
        with patch.object(ports,'ROOT',self.root), patch.object(ports,'LOCKFILE',lockfile):
            self.assertEqual(list(ports.packages()),[(package,target)])
        self.assertEqual(target.read_bytes(),BODY)
        self.assertEqual(self.requests,0)


if __name__=='__main__':
    unittest.main()

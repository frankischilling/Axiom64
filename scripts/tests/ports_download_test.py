# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise simultaneous actual cache writers through an owned HTTP server."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ports import download

BODY=bytes(range(256))*8192


class Downloads(unittest.TestCase):
    def setUp(self):
        self.workspace=tempfile.TemporaryDirectory(prefix='axiom64-download-cache-')
        self.addCleanup(self.workspace.cleanup)
        self.root=Path(self.workspace.name)
        self.release=threading.Event()
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
                self.send_response(200)
                self.send_header('Content-Length',str(len(BODY)))
                self.end_headers()
                if owner.release.wait(5):
                    self.wfile.write(BODY)
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


if __name__=='__main__':
    unittest.main()

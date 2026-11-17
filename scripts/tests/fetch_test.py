#!/usr/bin/env python3
"""Check pinned dependency downloads through real local HTTP endpoints."""
import hashlib
import http.server
import importlib.util
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error


class FetchTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom-locked-fetch-')
        self.root = Path(self.temporary.name)
        self.requests = []
        self.payload = b'locked source archive\x00\xff\n'
        self.routes = {}
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(self.path)
                status, body = owner.routes.get(self.path, (503, b'unavailable'))
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.worker = threading.Thread(target=self.server.serve_forever,
                                       kwargs={'poll_interval': 0.01}, daemon=True)
        self.worker.start()
        base = 'http://127.0.0.1:' + str(self.server.server_port)
        script = Path(__file__).resolve().parents[1] / 'fetch.py'
        spec = importlib.util.spec_from_file_location('locked_fetch_fixture', script)
        self.fetcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.fetcher)
        self.fetcher.ROOT = self.root
        self.fetcher.LOCK = {'fixture': dict(
            url=base + '/primary', mirrors=[base + '/mirror-one', base + '/mirror-two'],
            archive='fixture.tar.bz2', sha256=hashlib.sha256(self.payload).hexdigest())}
        self.destination = self.root / 'downloads/fixture.tar.bz2'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.assertFalse(self.worker.is_alive())
        self.temporary.cleanup()

    def test_primary_success_uses_only_one_endpoint(self):
        self.routes['/primary'] = 200, self.payload
        self.assertEqual(self.fetcher.fetch('fixture').read_bytes(), self.payload)
        self.assertEqual(self.requests, ['/primary'])

    def test_unavailable_primary_uses_pinned_mirror(self):
        self.routes['/mirror-one'] = 200, self.payload
        self.assertEqual(self.fetcher.fetch('fixture').read_bytes(), self.payload)
        self.assertEqual(self.requests, ['/primary', '/mirror-one'])

    def test_second_mirror_fits_the_original_three_attempt_bound(self):
        self.routes['/mirror-two'] = 200, self.payload
        self.assertEqual(self.fetcher.fetch('fixture').read_bytes(), self.payload)
        self.assertEqual(self.requests, ['/primary', '/mirror-one', '/mirror-two'])

    def test_all_endpoints_unavailable_preserves_last_error(self):
        with self.assertRaises(urllib.error.HTTPError) as failure:
            self.fetcher.fetch('fixture')
        self.addCleanup(failure.exception.close)
        self.assertTrue(failure.exception.url.endswith('/mirror-two'))
        self.assertEqual(self.requests, ['/primary', '/mirror-one', '/mirror-two'])
        self.assertFalse(self.destination.exists())

    def test_dependency_without_mirrors_keeps_three_attempts(self):
        del self.fetcher.LOCK['fixture']['mirrors']
        with self.assertRaises(urllib.error.HTTPError) as failure:
            self.fetcher.fetch('fixture')
        self.addCleanup(failure.exception.close)
        self.assertEqual(self.requests, ['/primary', '/primary', '/primary'])

    def test_verified_cache_needs_no_network(self):
        self.destination.parent.mkdir()
        self.destination.write_bytes(self.payload)
        self.assertEqual(self.fetcher.fetch('fixture'), self.destination)
        self.assertEqual(self.requests, [])

    def test_changed_cache_fails_without_fallback(self):
        self.destination.parent.mkdir()
        self.destination.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
            self.fetcher.fetch('fixture')
        self.assertEqual(self.requests, [])

    def test_changed_mirror_bytes_never_publish_or_try_another_source(self):
        self.routes['/mirror-one'] = 200, b'changed'
        self.routes['/mirror-two'] = 200, self.payload
        with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
            self.fetcher.fetch('fixture')
        self.assertEqual(self.requests, ['/primary', '/mirror-one'])
        self.assertFalse(self.destination.exists())

    def test_old_partial_bytes_are_replaced_before_publishing(self):
        self.destination.parent.mkdir()
        self.destination.with_suffix('.bz2.part').write_bytes(b'old partial bytes')
        self.routes['/mirror-one'] = 200, self.payload
        self.assertEqual(self.fetcher.fetch('fixture').read_bytes(), self.payload)
        self.assertFalse(self.destination.with_suffix('.bz2.part').exists())


if __name__ == '__main__':
    unittest.main()

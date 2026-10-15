#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep signed source-index identity stable during actual HTTP publication changes."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from file_capabilities.host_sources import authenticated_index


class HostSourceIndexTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom64-host-source-index-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.output = self.root / 'evidence'
        self.data = b'original authenticated compressed index'
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.signed = self.root / 'InRelease'
        # Signature verification belongs to capture(), before this index helper.
        self.signed.write_text('SHA256:\n ' + self.digest + ' ' + str(len(self.data)) +
                               ' main/source/Sources.xz\n')
        self.requests = []
        self.served = self.data
        self.status = 200
        self.declared_size = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(self.path)
                data = (b'newly published mutable source index' if
                        self.path.endswith('/main/source/Sources.xz') else owner.served)
                self.send_response(owner.status)
                self.send_header('Content-Length', str(owner.declared_size or len(data)))
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True

            def log_message(self, *arguments):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.mirror = 'http://127.0.0.1:' + str(self.server.server_port) + '/ubuntu/'
        self.index = self.cache / 'noble-updates-Sources.xz'

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def fetch(self):
        return authenticated_index(self.signed, self.cache, self.output, 'noble-updates', self.mirror)

    def proof(self):
        return json.loads((self.output / 'archive-authentication/noble-updates/fetch.json').read_text())

    def test_publication_change_uses_the_authenticated_hash_path(self):
        mutable = self.mirror + 'dists/noble-updates/main/source/Sources.xz'
        with urllib.request.urlopen(mutable, timeout=5) as response:
            self.assertNotEqual(hashlib.sha256(response.read()).hexdigest(), self.digest)
        result = self.fetch()
        self.assertEqual(result.read_bytes(), self.data)
        self.assertEqual(self.requests, ['/ubuntu/dists/noble-updates/main/source/Sources.xz',
                                        '/ubuntu/dists/noble-updates/main/source/by-hash/SHA256/' + self.digest])
        self.assertTrue(self.proof()['passed'])
        self.assertEqual(list(self.cache.glob('*.part')), [])

    def test_changed_index_is_rejected_and_retained(self):
        self.served = b'X' * len(self.data)
        with self.assertRaisesRegex(ValueError, 'checksum differs'):
            self.fetch()
        self.assertFalse(self.index.exists())
        self.assertFalse(self.proof()['passed'])
        self.assertEqual((self.output / 'archive-authentication/noble-updates/Sources.xz').read_bytes(), self.served)
        self.assertEqual(self.proof()['actual_sha256'], hashlib.sha256(self.served).hexdigest())

    def test_short_response_is_not_committed(self):
        self.served = self.data[:-1]
        with self.assertRaisesRegex(ValueError, 'checksum differs'):
            self.fetch()
        self.assertFalse(self.index.exists())
        self.assertEqual(self.proof()['actual_bytes'], len(self.served))

    def test_aborted_content_length_retains_partial_bytes(self):
        self.served = self.data[:-3]
        self.declared_size = len(self.data)
        with self.assertRaisesRegex(ValueError, 'checksum differs'):
            self.fetch()
        self.assertFalse(self.index.exists())
        self.assertEqual(self.proof()['interrupted'], 'incomplete HTTP response')
        self.assertEqual(self.proof()['actual_bytes'], len(self.served))

    def test_complete_cached_index_is_verified_without_network(self):
        self.index.write_bytes(self.data)
        self.assertEqual(self.fetch().read_bytes(), self.data)
        self.assertEqual(self.requests, [])
        self.assertTrue(self.proof()['cached'])

    def test_damaged_cache_is_rejected_without_replacement(self):
        self.index.write_bytes(b'damaged retained cache')
        with self.assertRaisesRegex(ValueError, 'checksum differs'):
            self.fetch()
        self.assertEqual(self.requests, [])
        self.assertEqual(self.index.read_bytes(), b'damaged retained cache')

    def test_missing_hash_does_not_fall_back_to_a_mutable_url(self):
        self.status = 404
        with self.assertRaises(urllib.error.HTTPError):
            self.fetch()
        self.assertEqual(len(self.requests), 1)
        self.assertIn('/by-hash/SHA256/', self.requests[0])
        self.assertEqual(self.proof()['status'], 404)
        self.assertFalse(self.index.exists())

    def test_missing_signed_index_is_rejected_before_network(self):
        self.signed.write_text('SHA256:\n')
        with self.assertRaisesRegex(ValueError, 'lacks the Sources index'):
            self.fetch()
        self.assertEqual(self.requests, [])


if __name__ == '__main__':
    unittest.main()

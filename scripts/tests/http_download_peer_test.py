#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep certificate-rejection observation strict before and after TLS completion."""
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from http_download.peer import Peer
from http_download_test import peer_results
from random_crypto.peer import certificates


class CertificateRejectionObservation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='axiom64-http-peer-test-')
        cls.certificates = Path(cls.temporary.name) / 'certificates'
        certificates(cls.certificates, Path('/usr/bin/openssl'))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def exchange(self, name, request):
        peer = Peer(name, self.certificates, 5)
        self.addCleanup(lambda: peer.close() if not peer.result['closed'] else None)
        context = ssl.create_default_context(cafile=str(self.certificates / 'ca.pem'))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        # All test connections verify the actual CA and certificate name. The
        # rejection-labelled cell must still reject any observed HTTP request.
        with socket.create_connection(('127.0.0.1', peer.port), timeout=2) as connection:
            with context.wrap_socket(connection, server_hostname='axiom64.test') as client:
                if request:
                    client.sendall(request)
                    if request.endswith(b'\r\n\r\n'):
                        self.assertTrue(client.recv(4096).startswith(b'HTTP/1.1 200 OK\r\n'))
        end = time.monotonic() + 2
        while time.monotonic() < end:
            value = peer.result
            if (value['requests'] or value['errors'] or value['rejected_handshakes'] or
                value.get('rejected_after_handshake')):
                break
            time.sleep(.01)
        peer.close()
        return peer

    def test_no_http_after_completed_tls_is_recorded_separately(self):
        peer = self.exchange('hostname', b'')
        self.assertEqual(peer_results({'hostname': peer})['hostname']['requests'], [])
        self.assertEqual(peer.result['rejected_handshakes'], [])
        self.assertEqual(len(peer.result['rejected_after_handshake']), 1)
        self.assertEqual(peer.result['rejected_after_handshake'][0]['application_bytes'], 0)

    def test_partial_http_is_not_relabelled_certificate_rejection(self):
        peer = self.exchange('hostname', b'G')
        self.assertEqual(peer.result['rejected_after_handshake'], [])
        self.assertTrue(peer.result['errors'])
        with self.assertRaisesRegex(RuntimeError, 'native HTTP peer failed'):
            peer_results({'hostname': peer})

    def test_complete_http_fails_the_required_rejection_cell(self):
        peer = self.exchange('hostname', b'GET /small HTTP/1.1\r\nHost: wrong.test\r\n\r\n')
        self.assertEqual(len(peer.result['requests']), 1)
        with self.assertRaisesRegex(RuntimeError, 'invalid certificate received HTTP application data'):
            peer_results({'hostname': peer})

    def test_valid_peer_still_requires_http_application_data(self):
        peer = self.exchange('tls13', b'')
        self.assertEqual(peer.result['rejected_after_handshake'], [])
        self.assertTrue(peer.result['errors'])
        with self.assertRaisesRegex(RuntimeError, 'native HTTP peer failed'):
            peer_results({'tls13': peer})

    def test_stalled_tls_handshake_stops_before_client_closes(self):
        peer = Peer('tls13', self.certificates, 30)
        client = socket.create_connection(('127.0.0.1', peer.port), timeout=2)
        try:
            end = time.monotonic() + 2
            while time.monotonic() < end:
                connection = peer.connection
                if connection is not None and (isinstance(connection, ssl.SSLSocket) or
                                               connection.fileno() == -1):
                    break
                time.sleep(.005)
            self.assertIsNotNone(peer.connection, 'peer did not accept the stalled client')
            started = time.monotonic()
            peer.close()
            self.assertLess(time.monotonic() - started, 2)
            self.assertFalse(peer.thread.is_alive())
            self.assertTrue(peer.result['closed'])
            self.assertEqual(peer.result['requests'], [])
            self.assertEqual(peer.result['errors'], [])
        finally:
            client.close()
            peer.thread.join(timeout=3)
            if not peer.thread.is_alive():
                peer.close()


if __name__ == '__main__':
    unittest.main()

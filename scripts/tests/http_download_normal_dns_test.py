#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay actual guest questions that exposed the normal DNS fixture's A-only parser."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from http_download.normal_peer import dns_reply
from http_download.log import healthy

# Exact A and AAAA questions retained from the failed normal guest capture.
QUESTIONS = (
    'd68d01000001000000000000056c616e6530076178696f6d363404746573740000010001',
    '6ea601000001000000000000056c616e6530076178696f6d3634047465737400001c0001',
)


class NormalDnsAndLogs(unittest.TestCase):
    def test_actual_A_and_AAAA_receive_corresponding_replies(self):
        for index, encoded in enumerate(QUESTIONS):
            query = bytes.fromhex(encoded)
            name, answer = dns_reply(query)
            self.assertEqual(name, 'lane0.axiom64.test')
            self.assertEqual(answer[:2], query[:2])
            self.assertEqual(answer[12:len(query)], query[12:])
            self.assertEqual(struct.unpack_from('!5H', answer, 2), (0x8180, 1, 1-index, 0, 0))
            self.assertEqual(answer[len(query):] if index else answer[-4:], b'' if index else bytes((10,23,1,1)))

    def test_unexpected_question_type_is_rejected(self):
        query = bytes.fromhex(QUESTIONS[0])[:-4]+b'\0\x0f\0\1'
        with self.assertRaisesRegex(ValueError, 'IN A or AAAA'):
            dns_reply(query)

    def test_wrong_certificate_name_still_resolves_to_the_owned_peer(self):
        query = bytes.fromhex(QUESTIONS[0]).replace(b'\x05lane0', b'\x06wrong0')
        name, answer = dns_reply(query)
        self.assertEqual(name, 'wrong0.axiom64.test')
        self.assertEqual(answer[-4:], bytes((10,23,1,1)))

    def test_fault_and_firmware_controls_reject_success_markers(self):
        valid = b'Firmware: BIOS\r\nAXIOM64_TESTS_PASS\r\nAXIOM64_EXIT status=0\r\n'
        self.assertTrue(healthy(valid, 'bios')['passed'])
        for changed in (valid.replace(b'BIOS', b'UEFI'), valid+b'PANIC: fixture\n',
                        valid+b'FAULT pid=12\n', valid+b'Assertion counter failed\n'):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                healthy(changed, 'bios')


if __name__ == '__main__':
    unittest.main()

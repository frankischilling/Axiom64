# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay measured device queries and retain rejected raw-reply changes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv6_device_inventory import observations

FIXTURES = ROOT / 'scripts/tests/fixtures'
REFERENCE = FIXTURES / 'ipv6-device-inventory-linux7.json'
ARCHIVE = None


def changed_reply(text, kind):
    pattern = r'^LINK_RAW kind=reply sequence=1 datagram=0 bytes=(\d+) hex=([0-9a-f]+)$'
    matches = list(re.finditer(pattern, text, re.M))
    if len(matches) != 1:
        raise ValueError('one actual first direct reply')
    match = matches[0]
    data = bytearray.fromhex(match[2])
    if kind == 'flags':
        struct.pack_into('<I', data, 24, 0x11042)
        replacement = ('flags', '11042')
    elif kind == 'mtu':
        at = 32
        while at < len(data):
            length, field = struct.unpack_from('<HH', data, at)
            if field & 0x3fff == 4:
                struct.pack_into('<I', data, at + 4, 1492)
                break
            at += (length + 3) & ~3
        else:
            raise ValueError('actual direct link MTU attribute')
        replacement = ('mtu', '1492')
    else:
        struct.pack_into('<I', data, 8, 999)
        replacement = None
    line = f'LINK_RAW kind=reply sequence=1 datagram=0 bytes={len(data)} hex={data.hex()}'
    text = text[:match.start()] + line + text[match.end():]
    if replacement:
        rows = list(re.finditer(r'^LINK_QUERY .* sequence=1$', text, re.M))
        if len(rows) != 1:
            raise ValueError('one original first queried result')
        row = rows[0]
        value = re.sub(r'\b' + replacement[0] + r'=[0-9a-f]+',
                       replacement[0] + '=' + replacement[1], row[0])
        text = text[:row.start()] + value + text[row.end():]
    return text


class ActualDeviceInventory(unittest.TestCase):
    def setUp(self):
        self.reference = json.loads(REFERENCE.read_text())
        self.path = FIXTURES / 'ipv6-device-inventory-linux7.log'
        data = self.path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), self.reference['original_log_sha256'])
        self.text = data.decode()

    def test_actual_native_queries_and_current_source(self):
        self.assertEqual(hashlib.sha256((ROOT / 'userspace/tests/net/ipv6_device_inventory.c').read_bytes()).hexdigest(),
                         self.reference['source_sha256'])
        result = observations(self.text, self.reference)
        self.assertTrue(result['passed'], result)
        self.assertEqual((len(result['observations']), result['raw_transactions']), (60, 48))

    def test_original_retired_scope_and_link_watch_failures_stay_rejected(self):
        for label, value in self.reference['negative_fixtures'].items():
            with self.subTest(label=label):
                data = (FIXTURES / value['file']).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), value['log_sha256'])
                self.assertFalse(observations(data.decode(), self.reference)['passed'])

    def test_changed_raw_replies_and_matching_summary_are_rejected(self):
        variants = {kind: changed_reply(self.text, kind) for kind in ('flags', 'mtu', 'sequence')}
        variants['completion'] = self.text.replace(self.reference['complete_marker'], 'LINK_STATE_INCOMPLETE', 1)
        variants['request-family'] = re.sub(
            r'(^LINK_RAW kind=request sequence=1 datagram=0 bytes=32 hex=[0-9a-f]{32})00',
            r'\g<1>02', self.text, count=1, flags=re.M)
        variants['running-while-down'] = self.text.replace(
            'LINK_STATE action=administrative lane=0 stage=1 flags=1002',
            'LINK_STATE action=administrative lane=0 stage=1 flags=1042', 1)
        variants['missing-query'] = re.sub(r'^LINK_QUERY .* sequence=1\n', '', self.text, count=1, flags=re.M)
        variants['missing-reply'] = re.sub(r'^LINK_RAW kind=reply sequence=1 .*\n', '', self.text, count=1, flags=re.M)
        variants['summary-sequence'] = re.sub(r'(^LINK_QUERY .* sequence=)1$', r'\g<1>999',
                                              self.text, count=1, flags=re.M)
        results = {}
        for kind, text in variants.items():
            with self.subTest(kind=kind):
                self.assertNotEqual(text, self.text)
                result = observations(text, self.reference)
                self.assertFalse(result['passed'])
                results[kind] = dict(error=result.get('error'), complete=result['complete'])
        if ARCHIVE:
            with zipfile.ZipFile(ARCHIVE, 'x', zipfile.ZIP_DEFLATED) as saved:
                for kind, text in variants.items():
                    saved.writestr(kind + '.log', text.encode())
                saved.writestr('rejections.json', json.dumps(results, indent=2))
            with zipfile.ZipFile(ARCHIVE) as saved:
                self.assertIsNone(saved.testzip())
                for kind, text in variants.items():
                    data = saved.read(kind + '.log')
                    self.assertEqual(data, text.encode())
                    result = observations(data.decode(), self.reference)
                    self.assertFalse(result['passed'])
                    self.assertEqual(dict(error=result.get('error'), complete=result['complete']), results[kind])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path)
    args, remaining = parser.parse_known_args()
    ARCHIVE = args.archive
    unittest.main(argv=[sys.argv[0], *remaining])

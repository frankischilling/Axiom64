# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject serialized damage to actual IPv6 address-owner packets and observations."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ipv6_owner_capture import inspect
from ipv6_owner_damage import controls, COMMON, GLOBAL, LIFECYCLE, SECRET

FIXTURES=Path(__file__).resolve().parent/'fixtures'
ARCHIVE=None


class ActualOwnershipCapture(unittest.TestCase):
    def fixture(self,group):
        manifest=json.loads((FIXTURES/f'ipv6-owner-axiom-{group}.json').read_text())
        self.assertEqual((manifest['provider'],manifest['group']),('Axiom64',group))
        self.assertTrue(manifest['original_packet_timestamps_unchanged'])
        self.assertTrue(manifest['actual_image_independently_opened'])
        for name,metadata in manifest['files'].items():
            self.assertEqual(Path(name).name,name)
            data=(FIXTURES/name).read_bytes()
            self.assertEqual((len(data),hashlib.sha256(data).hexdigest()),(metadata['bytes'],metadata['sha256']))
        return (FIXTURES/f'ipv6-owner-axiom-{group}.log').read_text()

    def test_actual_global_and_lifecycle_packets(self):
        for group in ('global','lifecycle','secret'):
            text=self.fixture(group)
            for lane in range(2):
                with self.subTest(group=group,lane=lane):
                    result=inspect(FIXTURES/f'ipv6-owner-axiom-{group}-lane{lane}.pcap',lane,text,group)
                    self.assertTrue(result['passed'])
                    self.assertEqual(len(result['cases']),{'global':4,'lifecycle':5,'secret':2}[group])
                    self.assertEqual(len(result['actual_changed_secret_readbacks']),2 if group=='secret' else 0)

    def test_serialized_corruptions_are_rejected(self):
        for group,extra in [('global',GLOBAL),('lifecycle',LIFECYCLE),('secret',SECRET)]:
            with self.subTest(group=group):
                archive=ARCHIVE.with_name(ARCHIVE.stem+'-'+group+ARCHIVE.suffix) if ARCHIVE else None
                result=controls(FIXTURES/f'ipv6-owner-axiom-{group}-lane0.pcap',0,self.fixture(group),group,archive)
                self.assertEqual([row['control'] for row in result],list(COMMON+extra))
                self.assertTrue(all(row['rejection'] for row in result))


if __name__=='__main__':
    parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--archive',type=Path)
    arguments,remaining=parser.parse_known_args();ARCHIVE=arguments.archive
    unittest.main(argv=[sys.argv[0],*remaining])

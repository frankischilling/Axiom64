# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind protocol-listener metadata to real ordinary, fault and pressure executions."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from network_test import packet_protocol_observations

FIXTURES = Path(__file__).parent / 'fixtures/packet-protocol-observation'
ARCHIVE = None


class PacketProtocolObservations(unittest.TestCase):
    def test_actual_records_and_serialized_reopened_corruptions(self):
        manifest = json.loads((FIXTURES / 'manifest.json').read_text())
        self.assertEqual(manifest['schema'], 1)
        self.assertEqual(set(manifest['cases']), {'pair', 'eight', 'fault', 'pressure'})
        controls = []
        with tempfile.TemporaryDirectory(prefix='axiom64-protocol-observations-') as temporary:
            directory = Path(temporary)
            archive = ARCHIVE or directory / 'negative.zip'
            if ARCHIVE:
                archive.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
                for label, record in manifest['cases'].items():
                    with self.subTest(case=label):
                        self.assertTrue(record['original_producer_passed'])
                        self.assertFalse(record['full_matrix_acceptance'])
                        path = FIXTURES / label / 'serial.log'
                        data = path.read_bytes()
                        self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                                         (record['files']['serial.log']['bytes'],
                                          record['files']['serial.log']['sha256']))
                        text = data.decode().replace('\r\n', '\n')
                        indices = record['indices']
                        result = packet_protocol_observations(text, indices)
                        self.assertTrue(result['passed'])
                        self.assertEqual(result['passes'], indices)
                        if indices:
                            query = 'PACKET_PROTOCOL_OBSERVATION index=1 type=0 length=64'
                            complete = 'PACKET_PROTOCOL_PASS index=1'
                            lines = text.splitlines()
                            first, second = lines.index(query), lines.index(complete)
                            lines[first], lines[second] = lines[second], lines[first]
                            variants = [text.replace(query, query.replace('type=0', 'type=4'), 1),
                                        text.replace(query + '\n', '', 1), text + complete + '\n',
                                        text.replace(query, query.replace('length=64', 'length=65'), 1),
                                        text.replace(query, query.replace('index=1', 'index=9'), 1),
                                        '\n'.join(lines) + '\n']
                        else:
                            variants = [text + 'PACKET_PROTOCOL_OBSERVATION index=1 type=0 length=64\n',
                                        text + 'PACKET_PROTOCOL_PASS index=1\n']
                        for number, changed in enumerate(variants):
                            self.assertNotEqual(changed, text)
                            self.assertFalse(packet_protocol_observations(changed, indices)['passed'])
                            name = f'{label}-{number}.log'
                            payload = changed.encode()
                            saved.writestr(name, payload)
                            controls.append((name, indices, hashlib.sha256(payload).hexdigest()))
                        self.assertEqual(path.read_bytes(), data)
            with zipfile.ZipFile(archive) as saved:
                self.assertIsNone(saved.testzip())
                self.assertEqual(len(saved.namelist()), 16)
                for name, indices, fingerprint in controls:
                    target = directory / ('fresh-' + name)
                    target.write_bytes(saved.read(name))
                    self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), fingerprint)
                    self.assertFalse(packet_protocol_observations(target.read_text(), indices)['passed'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--archive', type=Path)
    arguments, remaining = parser.parse_known_args()
    ARCHIVE = arguments.archive
    unittest.main(argv=[sys.argv[0], *remaining])
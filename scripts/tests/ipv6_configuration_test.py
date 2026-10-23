#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject damaged IPv6 configuration ABI observations."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from ipv6_configuration_test import observations, REFERENCE


class ConfigurationObservations(unittest.TestCase):
    def setUp(self):
        records = json.loads((ROOT / REFERENCE).read_text())['observations']
        self.text = '\n'.join([*records, 'SYSCTL_IO_COMPLETE counted=30',
                               'SYSCTL_FRONTEND_COMPLETE']) + '\n'

    def test_measured_records(self):
        self.assertTrue(observations(self.text)['passed'])

    def test_result_damage_and_missing_evidence(self):
        mutations = [
            self.text.replace('label=fault-combined result=-1 error=14',
                              'label=fault-combined result=-1 error=22'),
            self.text.replace('IO_READ_VECTOR result=2 error=0 offset=2',
                              'IO_READ_VECTOR result=2 error=0 offset=0'),
            self.text.replace('label=invalid-combined result=-1 error=22 offset=0 value=0',
                              'label=invalid-combined result=-1 error=22 offset=0 value=1'),
            self.text.replace('IO_SECRET_READ scope=all mode=600', 'IO_SECRET_READ scope=all mode=644'),
            self.text.replace('IO_SECRET_WRITE scope=eth0 result=-1 error=5 offset=0\n', ''),
            self.text + 'IO_SECRET_WRITE scope=eth0 result=-1 error=5 offset=0\n',
            self.text.replace('SYSCTL_FRONTEND_COMPLETE\n', ''),
            self.text + 'SYSCTL_FRONTEND_COMPLETE\n',
            self.text + 'SYSCTL_IO_FATAL errno=14\n',
        ]
        for number, text in enumerate(mutations):
            with self.subTest(mutation=number):
                self.assertNotEqual(text, self.text)
                self.assertFalse(observations(text)['passed'])


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject damaged IPv6 configuration ABI observations."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
import ipv6_configuration_test as configuration
from ipv6_configuration_test import observations, guest_identity, REFERENCE


class ConfigurationObservations(unittest.TestCase):
    def setUp(self):
        records = json.loads((ROOT / REFERENCE).read_text())['observations']
        self.text = '\n'.join([*records, 'SYSCTL_IO_COMPLETE counted=30',
                               'SYSCTL_FRONTEND_COMPLETE', 'SYSCTL_MAX_ADDRESSES_COMPLETE']) + '\n'

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
            self.text.replace('IO_MAX_SCOPE label=all all=1 default=16 eth0=2 eth1=16 lo=16',
                              'IO_MAX_SCOPE label=all all=1 default=16 eth0=1 eth1=16 lo=16'),
            self.text.replace('label=negative name=max_addresses result=3 error=0 value=-1',
                              'label=negative name=max_addresses result=-1 error=22 value=2'),
            self.text.replace('SYSCTL_MAX_ADDRESSES_COMPLETE\n', ''),
            self.text + 'SYSCTL_MAX_ADDRESSES_COMPLETE\n',
        ]
        for number, text in enumerate(mutations):
            with self.subTest(mutation=number):
                self.assertNotEqual(text, self.text)
                self.assertFalse(observations(text)['passed'])

    def test_actual_guest_transport(self):
        text = 'Firmware: BIOS\nvirtio-net: index=1 transport=modern\nvirtio-net: index=2 transport=modern\n'
        self.assertTrue(guest_identity(text, 'bios', 'modern'))
        self.assertFalse(guest_identity(text, 'bios', 'legacy'))
        self.assertFalse(guest_identity(text, 'uefi', 'modern'))
        self.assertFalse(guest_identity(text.replace('index=2', 'index=3'), 'bios', 'modern'))
        legacy = text.replace('modern', 'legacy')
        self.assertTrue(guest_identity(legacy, 'bios', 'legacy'))
        self.assertFalse(guest_identity(legacy, 'bios', 'modern'))


class LinkConfigurationObservations(unittest.TestCase):
    def setUp(self):
        reference = 'scripts/tests/fixtures/ipv6-link-configuration-linux7.json'
        self.records = json.loads((ROOT / reference).read_text())['observations']
        self.text = '\n'.join([*self.records, 'LINK_IO_COMPLETE parent=38 child=1']) + '\n'
        self.settings = patch.multiple(configuration, LINK_MODE=True, REFERENCE=reference)
        self.settings.start()
        self.addCleanup(self.settings.stop)

    def test_actual_mode_and_error_records(self):
        self.assertTrue(observations(self.text)['passed'])
        mutations = [
            self.text.replace('result=-34', 'result=-22'),
            self.text.replace('result=-1 mode=1', 'result=0 mode=1'),
            self.text.replace('query=0 observed=3', 'query=0 observed=1'),
            self.text.replace('query6=0 observed6=2', 'query6=0 observed6=-1'),
            self.text.replace('LINK_IO_COMPLETE parent=38 child=1\n', ''),
            self.text + 'LINK_IO_COMPLETE parent=38 child=1\n',
            self.text + 'LINK_IO_FATAL errno=14\n',
            self.text.replace(self.records[0] + '\n', ''),
            self.text + self.records[0] + '\n',
        ]
        for number, text in enumerate(mutations):
            with self.subTest(mutation=number):
                self.assertNotEqual(text, self.text)
                self.assertFalse(observations(text)['passed'])


class LifetimeConfigurationObservations(unittest.TestCase):
    def test_audited_release_selection(self):
        self.assertTrue(configuration.lifetime_reference().endswith('-linux7.json'))
        self.assertTrue(configuration.lifetime_reference('6.17.0-1022-azure').endswith('-linux617.json'))
        self.assertTrue(configuration.lifetime_reference('7.0.0-1017-azure').endswith('-linux7.json'))
        with self.assertRaisesRegex(ValueError, 'audited Linux release'):
            configuration.lifetime_reference('7.0.0-unknown')

    def test_actual_retirement_defaults_and_retained_descriptions(self):
        for label in ('linux617', 'linux7'):
            reference = 'scripts/tests/fixtures/ipv6-configuration-lifetime-' + label + '.json'
            fixture = json.loads((ROOT / reference).read_text())
            text = '\n'.join([*fixture['observations'], fixture['complete_marker']]) + '\n'
            with patch.multiple(configuration, LIFETIME_MODE=True, REFERENCE=reference):
                self.assertTrue(observations(text)['passed'])
                selected = next(line for line in fixture['observations']
                                if 'action=1 stage=1 retained=max_addresses seek=0' in line)
                mutations = [text.replace(selected, selected.replace('read=-1 errno=2', 'read=0 errno=0')),
                             text.replace('retained_stat=-1 retained_errno=2',
                                          'retained_stat=0 retained_errno=0'),
                             text.replace('retained_directory_open=0 errno=2',
                                          'retained_directory_open=1 errno=0'),
                             text.replace('same_inode=0 retained_stat=-1',
                                          'same_inode=1 retained_stat=-1'),
                             text.replace('read=2 errno=0 bytes=370a',
                                          'read=2 errno=0 bytes=330a'),
                             text.replace(fixture['complete_marker'] + '\n', ''),
                             text + fixture['complete_marker'] + '\n',
                             text + 'LIFETIME_IO_FATAL errno=14\n']
                for number, damaged in enumerate(mutations):
                    with self.subTest(label=label, mutation=number):
                        self.assertNotEqual(damaged, text)
                        self.assertFalse(observations(damaged)['passed'])


class SocketConfigurationObservations(unittest.TestCase):
    def setUp(self):
        reference = 'scripts/tests/fixtures/ipv6-socket-configuration-linux7.json'
        self.records = json.loads((ROOT / reference).read_text())['observations']
        self.text = '\n'.join([*self.records, 'SOCKET_IO_COMPLETE']) + '\n'
        self.settings = patch.multiple(configuration, SOCKET_MODE=True, REFERENCE=reference)
        self.settings.start()
        self.addCleanup(self.settings.stop)

    def test_actual_binding_and_control_records(self):
        self.assertTrue(observations(self.text)['passed'])
        mutations = [
            self.text.replace('size=40 result=0 errno=0', 'size=40 result=-1 errno=22'),
            self.text.replace('case=ordinary-same size=40 result=-1 errno=1',
                              'case=ordinary-same size=40 result=0 errno=0'),
            self.text.replace('41:8:20:77,', '41:8:20:-1,'),
            self.text.replace('41:8:20:64,', ''),
            self.text.replace('41:8:16:-1,', ''),
            self.text.replace('flags=8 used=40', 'flags=0 used=40'),
            self.text.replace('SOCKET_IO_COMPLETE\n', ''),
            self.text + 'SOCKET_IO_COMPLETE\n',
            self.text + 'SOCKET_IO_FATAL errno=14\n',
            self.text.replace(self.records[0] + '\n', ''),
            self.text + self.records[0] + '\n',
        ]
        for number, text in enumerate(mutations):
            with self.subTest(mutation=number):
                self.assertNotEqual(text, self.text)
                self.assertFalse(observations(text)['passed'])


if __name__ == '__main__':
    unittest.main()

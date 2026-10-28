# SPDX-License-Identifier: GPL-3.0-or-later
"""Original Linux query packets and constructed timer-proof rejection controls."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ipv4_multicast_capture import lane, query_timer_upper
from native_multicast_timers import CONFIG, AFTER_CONFIG, begin, finish, upper_microseconds

FIXTURE=Path(__file__).resolve().parent/'fixtures/ipv4-multicast-native-timers'


class NativeMulticastTimers(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='axiom-native-multicast-timers-')
        self.addCleanup(self.temporary.cleanup)
        self.case=Path(self.temporary.name)
        manifest=json.loads((FIXTURE/'manifest.json').read_text())
        self.assertTrue(manifest['diagnostic_only']);self.assertFalse(manifest['feature_acceptance'])
        for name,row in manifest['files'].items():
            body=(FIXTURE/name).read_bytes()
            self.assertEqual((len(body),hashlib.sha256(body).hexdigest()),(row['bytes'],row['sha256']))
            (self.case/name).write_bytes(body)
        self.statistics=json.loads((self.case/'statistics.json').read_text())
        # Deliberately constructed guard inputs exercise only the reader
        # contract; they do not supply missing proof for the original run.
        for name in (CONFIG,AFTER_CONFIG):
            (self.case/name).write_bytes(b'CONFIG_64BIT=y\nCONFIG_HZ=1000\n')
        self.policy=dict(schema=1,kernel='7.0.0-1017-azure',
            config_sha256=hashlib.sha256((self.case/CONFIG).read_bytes()).hexdigest(),
            before_ns=min(row['clock_start']['receipt_monotonic_ns'] for row in self.statistics)-1,
            after_ns=max(row['clock_end']['receipt_monotonic_after_ns'] for row in self.statistics)+1,
            upper_us=upper_microseconds())

    def upper(self,policy):
        return query_timer_upper(self.case,dict(native=True,native_timer_policy=policy,
            native_kernel_release='7.0.0-1017-azure',capture_statistics=self.statistics))

    def test_original_query_requires_a_verified_native_contract(self):
        self.assertEqual(self.upper(None),1010000)
        with self.assertRaisesRegex(ValueError,'actual unscaled query-response interval'):
            lane(self.case/'lane0.pcap',0,True,self.statistics[0])
        upper=self.upper(self.policy)
        self.assertEqual(upper,1075000)
        for number in range(2):
            self.assertEqual(lane(self.case/f'lane{number}.pcap',number,True,self.statistics[number],upper)['lane'],number)

    def test_reopened_policy_changes_reject(self):
        for key,value in [('schema',2),('kernel','6.17.0-1022-azure'),('upper_us',2000000),
            ('config_sha256','0'*64),('before_ns',self.policy['after_ns']),
            ('after_ns',self.policy['before_ns']),('upper_us',True)]:
            with self.subTest(key=key,value=value):
                policy=copy.deepcopy(self.policy);policy[key]=value
                path=self.case/'changed.json';path.write_text(json.dumps(policy))
                with self.assertRaises(ValueError):self.upper(json.loads(path.read_text()))

    def test_actual_configuration_is_required_before_and_after(self):
        (self.case/AFTER_CONFIG).write_bytes(b'CONFIG_64BIT=y\nCONFIG_HZ=250\n')
        with self.assertRaisesRegex(ValueError,'fingerprint'):self.upper(self.policy)
        (self.case/CONFIG).write_bytes((self.case/AFTER_CONFIG).read_bytes())
        policy=copy.deepcopy(self.policy)
        policy['config_sha256']=hashlib.sha256((self.case/CONFIG).read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,'CONFIG_HZ=1000'):self.upper(policy)

    def test_configuration_observations_must_bracket_all_captures(self):
        policy=copy.deepcopy(self.policy)
        policy['before_ns']=max(row['clock_start']['receipt_monotonic_ns'] for row in self.statistics)+1
        with self.assertRaisesRegex(ValueError,'bracket every actual capture'):self.upper(policy)

    def test_guest_cannot_use_the_native_allowance(self):
        self.assertEqual(query_timer_upper(self.case,dict(native=False)),1010000)
        with self.assertRaisesRegex(ValueError,'cannot alter a guest'):
            query_timer_upper(self.case,dict(native=False,native_timer_policy=self.policy))

    def test_collector_records_the_actual_supported_kernel_configuration(self):
        body=b'CONFIG_64BIT=y\nCONFIG_HZ=1000\n'
        for kernel in ('6.17.0-1022-azure','7.0.0-1017-azure'):
            with self.subTest(kernel=kernel), patch('native_multicast_timers.platform.release',return_value=kernel), \
                 patch('native_multicast_timers.read_configuration',return_value=body):
                started=begin(self.case);policy=finish(self.case,started)
                self.assertEqual(policy['kernel'],kernel)
                self.assertEqual(policy['upper_us'],1075000)
                self.assertLess(policy['before_ns'],policy['after_ns'])
                self.assertEqual((self.case/CONFIG).read_bytes(),body)
                self.assertEqual((self.case/AFTER_CONFIG).read_bytes(),body)

    def test_failed_final_configuration_is_preserved(self):
        body=b'CONFIG_64BIT=y\nCONFIG_HZ=1000\n';changed=b'CONFIG_64BIT=y\nCONFIG_HZ=250\n'
        with patch('native_multicast_timers.platform.release',return_value='7.0.0-1017-azure'), \
             patch('native_multicast_timers.read_configuration',side_effect=[body,changed]):
            started=begin(self.case)
            with self.assertRaisesRegex(ValueError,'CONFIG_HZ=1000'):finish(self.case,started)
        self.assertEqual((self.case/CONFIG).read_bytes(),body)
        self.assertEqual((self.case/AFTER_CONFIG).read_bytes(),changed)

    def test_unknown_kernel_keeps_the_original_contract(self):
        with patch('native_multicast_timers.platform.release',return_value='7.0.0-1018-azure'), \
             patch('native_multicast_timers.read_configuration') as configuration:
            self.assertIsNone(begin(self.case));configuration.assert_not_called()


if __name__=='__main__':unittest.main()

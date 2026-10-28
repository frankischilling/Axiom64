# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay actual late Linux packets and reject unowned timer-policy allowances."""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ipv6_device_pending_capture import inspect
from native_ipv6_timers import CONFIG, VALUES, EXPECTED, KERNEL, begin, finish, upper_microseconds

FIXTURE=Path(__file__).resolve().parent/'fixtures/ipv6-device-native-timers'


class NativeTimerPolicy(unittest.TestCase):
    fixture=FIXTURE
    kernel=KERNEL
    lane=0
    late_us=3111820

    def setUp(self):
        self.workspace=tempfile.TemporaryDirectory(prefix='axiom64-native-timer-policy-')
        self.addCleanup(self.workspace.cleanup)
        self.case=Path(self.workspace.name)
        manifest=json.loads((self.fixture/'manifest.json').read_text())
        self.assertTrue(manifest['diagnostic_only'])
        self.assertFalse(manifest['feature_acceptance'])
        for name,record in manifest['files'].items():
            data=(self.fixture/name).read_bytes()
            self.assertEqual((len(data),hashlib.sha256(data).hexdigest()),(record['bytes'],record['sha256']))
            (self.case/name).write_bytes(data)
        self.text=(self.case/'serial.log').read_text()
        self.statistics=json.loads((self.case/'statistics.json').read_text())
        stamps=[int(value) for value in re.findall(r'^IPV6_DEVICE_CONTROL .* observed_ns=(\d+)$',self.text,re.MULTILINE)]
        self.assertTrue(stamps)
        self.values=dict(before=dict(begin_ns=min(stamps)-2000,end_ns=min(stamps)-1000,values=dict(EXPECTED)),
                         after=dict(begin_ns=max(stamps)+1000,end_ns=max(stamps)+2000,values=dict(EXPECTED)))
        # These deliberately constructed guard inputs qualify only the reader's
        # contract. The packet/clock data above remains the original failed run.
        (self.case/CONFIG).write_text('CONFIG_64BIT=y\nCONFIG_HZ=1000\n')
        (self.case/VALUES).write_text(json.dumps(self.values))
        self.policy=dict(schema=1,kernel=self.kernel,
            config_sha256=hashlib.sha256((self.case/CONFIG).read_bytes()).hexdigest(),
            values_sha256=hashlib.sha256((self.case/VALUES).read_bytes()).hexdigest(),
            upper_us=upper_microseconds())

    def read(self, policy):
        return inspect(self.case/f'lane{self.lane}.pcap',self.lane,self.text,'carrier','regenerating',native=True,
            statistics=self.statistics,native_kernel_release=self.kernel,native_timer_policy=policy)

    def test_original_late_packets_require_the_recorded_native_contract(self):
        with self.assertRaisesRegex(ValueError,f'regeneration NA to ready real bound: {self.late_us}'):
            self.read(None)
        result=self.read(self.policy)
        self.assertTrue(result['passed'])
        self.assertEqual(result['observations']['ready_after_conflict_us'],self.late_us)
        self.assertEqual(result['regeneration_upper_us'],3212000)

    def test_reopened_changed_policy_proofs_reject(self):
        changes=(('wrong-kernel','kernel','6.17.0-1023-azure'),
                 ('wrong-schema','schema',2),('arbitrary-ceiling','upper_us',4000000),
                 ('missing-config-hash','config_sha256','0'*64),
                 ('missing-values-hash','values_sha256','0'*64))
        for name,key,value in changes:
            with self.subTest(control=name):
                altered=copy.deepcopy(self.policy);altered[key]=value
                path=self.case/(name+'.json');path.write_text(json.dumps(altered))
                with self.assertRaisesRegex(ValueError,'native DAD timer policy:'):
                    self.read(json.loads(path.read_text()))

    def test_another_supported_kernel_cannot_supply_this_runs_policy(self):
        changed=copy.deepcopy(self.policy)
        changed['kernel']='7.0.0-1017-azure' if self.kernel==KERNEL else KERNEL
        with self.assertRaisesRegex(ValueError,'actual supported native reference kernel'):
            self.read(changed)

    def test_matching_hash_does_not_admit_changed_actual_parameters(self):
        for scope in ('before','after'):
            with self.subTest(scope=scope):
                altered=copy.deepcopy(self.values)
                altered[scope]['values']['/proc/sys/net/ipv6/idgen_delay']='0\n'
                (self.case/VALUES).write_text(json.dumps(altered))
                policy=copy.deepcopy(self.policy)
                policy['values_sha256']=hashlib.sha256((self.case/VALUES).read_bytes()).hexdigest()
                with self.assertRaisesRegex(ValueError,'exact original .* parameters'):
                    self.read(policy)

    def test_matching_hash_does_not_admit_a_different_kernel_tick(self):
        (self.case/CONFIG).write_text('CONFIG_64BIT=y\nCONFIG_HZ=250\n')
        policy=copy.deepcopy(self.policy)
        policy['config_sha256']=hashlib.sha256((self.case/CONFIG).read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,'CONFIG_HZ=1000'):
            self.read(policy)

    def test_configuration_readbacks_must_bracket_the_actual_client(self):
        altered=copy.deepcopy(self.values)
        altered['before']['end_ns']=altered['after']['end_ns']
        (self.case/VALUES).write_text(json.dumps(altered))
        policy=copy.deepcopy(self.policy)
        policy['values_sha256']=hashlib.sha256((self.case/VALUES).read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            self.read(policy)

    def test_guest_cannot_select_the_native_allowance(self):
        case=FIXTURE.parent/'ipv6-device-pending/axiom-carrier-regenerating'
        text=(case/'serial.log').read_text()
        result=inspect(case/'lane0.pcap',0,text,'carrier','regenerating')
        self.assertEqual(result['regeneration_upper_us'],3100000)
        with self.assertRaisesRegex(ValueError,'native timer proof only applies'):
            inspect(case/'lane0.pcap',0,text,'carrier','regenerating',native_timer_policy=self.policy)

    def actual_parameters(self):
        values=dict(EXPECTED)
        # The proc interface reports this delay in seconds, while the neighbor
        # retransmission interface explicitly reports milliseconds.
        for lane in range(2):
            values[f'/proc/sys/net/ipv6/conf/eth{lane}/router_solicitation_delay']='1\n'
            values[f'/proc/sys/net/ipv6/neigh/eth{lane}/retrans_time_ms']='1000\n'
        return values

    def collect_begin(self, values):
        with patch('native_ipv6_timers.platform.release',return_value=self.kernel), \
             patch('native_ipv6_timers.Path.exists',return_value=True), \
             patch('native_ipv6_timers.Path.read_bytes',return_value=b'CONFIG_64BIT=y\nCONFIG_HZ=1000\n'), \
             patch('native_ipv6_timers.Path.read_text',lambda path:values[path.as_posix()]):
            return begin(self.case)

    def test_collector_accepts_actual_seconds_and_milliseconds_interfaces(self):
        started=self.collect_begin(self.actual_parameters())
        self.assertEqual(started['before']['values'],self.actual_parameters())

    def test_collector_completion_retains_the_original_running_kernel(self):
        started=self.collect_begin(self.actual_parameters())
        values=self.actual_parameters()
        with patch('native_ipv6_timers.platform.release',return_value=self.kernel), \
             patch('native_ipv6_timers.Path.read_text',lambda path:values[path.as_posix()]):
            completed=finish(self.case,started)
        self.assertEqual(completed['kernel'],self.kernel)
        self.assertEqual(completed['config_sha256'],started['config_sha256'])
        self.assertEqual(json.loads((self.case/'native-timer-policy.json').read_text()),completed)

    def test_rejected_initial_parameters_remain_as_raw_evidence(self):
        values=self.actual_parameters()
        values['/proc/sys/net/ipv6/conf/eth0/dad_transmits']='2\n'
        with self.assertRaisesRegex(ValueError,'dad_transmits'):
            self.collect_begin(values)
        self.assertEqual(json.loads((self.case/VALUES).read_text())['before']['values'],values)

    def test_rejected_final_parameters_preserve_both_observations(self):
        started=self.collect_begin(self.actual_parameters())
        values=self.actual_parameters()
        values['/proc/sys/net/ipv6/idgen_delay']='2\n'
        with patch('native_ipv6_timers.platform.release',return_value=self.kernel), \
             patch('native_ipv6_timers.Path.read_text',lambda path:values[path.as_posix()]):
            with self.assertRaisesRegex(ValueError,'idgen_delay'):
                finish(self.case,started)
        evidence=json.loads((self.case/VALUES).read_text())
        self.assertEqual(evidence['before'],started['before'])
        self.assertEqual(evidence['after']['values'],values)


class Linux7NativeTimerPolicy(NativeTimerPolicy):
    fixture=FIXTURE.parent/'ipv6-device-linux7-timers'
    kernel='7.0.0-1017-azure'
    lane=1
    late_us=3110848


if __name__=='__main__':
    unittest.main()

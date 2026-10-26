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

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ipv6_device_pending_capture import inspect
from native_ipv6_timers import CONFIG, VALUES, EXPECTED, upper_microseconds

FIXTURE=Path(__file__).resolve().parent/'fixtures/ipv6-device-native-timers'


class NativeTimerPolicy(unittest.TestCase):
    def setUp(self):
        self.workspace=tempfile.TemporaryDirectory(prefix='axiom64-native-timer-policy-')
        self.addCleanup(self.workspace.cleanup)
        self.case=Path(self.workspace.name)
        manifest=json.loads((FIXTURE/'manifest.json').read_text())
        self.assertTrue(manifest['diagnostic_only'])
        self.assertFalse(manifest['feature_acceptance'])
        for name,record in manifest['files'].items():
            data=(FIXTURE/name).read_bytes()
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
        self.policy=dict(schema=1,kernel='6.17.0-1022-azure',
            config_sha256=hashlib.sha256((self.case/CONFIG).read_bytes()).hexdigest(),
            values_sha256=hashlib.sha256((self.case/VALUES).read_bytes()).hexdigest(),
            upper_us=upper_microseconds())

    def read(self, policy):
        return inspect(self.case/'lane0.pcap',0,self.text,'carrier','regenerating',native=True,
            statistics=self.statistics,native_kernel_release='6.17.0-1022-azure',native_timer_policy=policy)

    def test_original_late_packets_require_the_recorded_native_contract(self):
        with self.assertRaisesRegex(ValueError,'regeneration NA to ready real bound: 3111820'):
            self.read(None)
        result=self.read(self.policy)
        self.assertTrue(result['passed'])
        self.assertEqual(result['observations']['ready_after_conflict_us'],3111820)
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


if __name__=='__main__':
    unittest.main()

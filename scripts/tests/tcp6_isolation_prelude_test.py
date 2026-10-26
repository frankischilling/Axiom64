# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay the real UEFI reader failure and preserve the original readiness seam."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ipv4_expiry_capture import read_capture
from tcp6.isolation_capture import inspect

FIXTURE=Path(__file__).parent/'fixtures/tcp6-isolation-prelude'


class Prelude(unittest.TestCase):
    def setUp(self):
        manifest=json.loads((FIXTURE/'manifest.json').read_text())
        for name,digest in manifest['files'].items():
            self.assertEqual(hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest(),digest)
        self.log=(FIXTURE/'client.log').read_text()
        self.rows=[read_capture(FIXTURE/f'lane{lane}.pcap') for lane in range(2)]
        self.assertIn('TCP6_ISOLATION_PASS rounds=4 zones=2 bytes_each=32 quiet_ms=50',self.log)

    def test_actual_complete_UEFI_conversations_keep_bounded_boot_preludes(self):
        for lane,rows in enumerate(self.rows):
            first=next(n for n,row in enumerate(rows) if row['frame'][12:14]==b'\x88\xc6')
            self.assertGreater(first,0)
            self.assertTrue(any(row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]!=58
                                for row in rows[:first]))
            self.assertTrue(inspect(rows,lane,self.log)['passed'])

    def test_original_boot_traffic_cannot_be_moved_into_the_ready_workload(self):
        for lane,rows in enumerate(self.rows):
            changed=copy.deepcopy(rows)
            first=next(n for n,row in enumerate(changed) if row['frame'][12:14]==b'\x88\xc6')
            before=next(row for row in changed[:first] if row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]!=58)
            moved=copy.deepcopy(before)
            moved['ns']=changed[first+1]['ns']
            changed.insert(first+2,moved)
            with self.assertRaisesRegex(ValueError,'neighbor maintenance'):
                inspect(changed,lane,self.log)

    def test_boot_prelude_still_requires_its_actual_interface_owner(self):
        changed=copy.deepcopy(self.rows[0])
        frame=bytearray(changed[0]['frame'])
        frame[11]^=1
        changed[0]['frame']=bytes(frame)
        with self.assertRaisesRegex(ValueError,'before readiness'):
            inspect(changed,0,self.log)

    def test_boot_prelude_remains_bounded(self):
        changed=copy.deepcopy(self.rows[0])
        prelude=copy.deepcopy(changed[0])
        changed=[copy.deepcopy(prelude) for _ in range(257)]+changed
        with self.assertRaisesRegex(ValueError,'before readiness'):
            inspect(changed,0,self.log)


if __name__=='__main__':
    unittest.main()

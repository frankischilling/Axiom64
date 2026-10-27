#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual two-adapter ownership client query/wait call chain."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from ipv6_owner_peer import Peer


class PairedOwnershipQueries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch=tempfile.TemporaryDirectory(prefix='axiom-owner-pair-unit-')
        cls.program=Path(cls.scratch.name)/'pair'
        subprocess.run(['gcc','-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror',
            '-Iuserspace/tests/net','userspace/tests/net/ipv6_owner_pair_host.c',
            '-o',str(cls.program)],cwd=ROOT,check=True)

    @classmethod
    def tearDownClass(cls):cls.scratch.cleanup()

    def exercise(self,mode):
        result=json.loads(subprocess.check_output([str(self.program),mode],cwd=ROOT,text=True))
        scenario=7 if mode=='link' else 8
        for lane,hexadecimal in enumerate(result['frames']):
            frame=bytes.fromhex(hexadecimal)
            peer=Peer(lane,'lifecycle',native=True)
            peer.case=scenario;peer.ready=True;peer.probes[scenario]={}
            peer.receive(frame)
            self.assertEqual(peer.pending['target'],frame[36:52])
            self.assertEqual(peer.pending['flags'],0x8c0 if mode=='link' else 0x40)
            self.assertEqual(peer.pending['guest_ns'],100000000000)
        self.assertEqual(result['first_wait_sent'],2)
        self.assertTrue(result['synthetic_timing_unit_model'])
        return result

    def test_link_queries_both_publish_before_the_first_blocking_wait(self):
        self.exercise('link')

    def test_existing_finite_global_pairing_preserves_fresh_metadata(self):
        self.exercise('global')

    def test_peer_still_rejects_ready_instead_of_tentative_conflict_owner(self):
        result=json.loads(subprocess.check_output([str(self.program),'link'],cwd=ROOT,text=True))
        frame=bytearray.fromhex(result['frames'][1]);frame[24:28]=(0x880).to_bytes(4,'big')
        peer=Peer(1,'lifecycle',native=True);peer.case=7;peer.ready=True;peer.probes[7]={}
        with self.assertRaisesRegex(ValueError,'queried exact selected conflict owner'):peer.receive(bytes(frame))


if __name__=='__main__':unittest.main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Lock down ownership policy selection and the actual conflict-before-ACK barrier."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ipv6_owner_peer import Peer
from ipv6_router_capture import qemu_records

FIXTURE=Path(__file__).resolve().parent/'fixtures/ipv6-owner-axiom-global-lane0.pcap'


class OwnershipPeer(unittest.TestCase):
    def guest_prefix(self):
        frames=[row['frame'] for row in qemu_records(FIXTURE) if row['frame'][6:12]==bytes.fromhex('525400123410')]
        stop=next(i for i,f in enumerate(frames) if f[12:14]==b'\x88\xc3' and f[20]==4)
        return frames[:stop+1]

    def prepared(self,drop_probe=False):
        peer=Peer(0,'global')
        frames=self.guest_prefix();request=frames[-1]
        target=request[36:52];probe=None
        for frame in frames[:-1]:
            if drop_probe and frame[12:14]==b'\x86\xdd' and frame[20]==58 and frame[54]==135 and frame[62:78]==target:
                probe=frame;continue
            peer.receive(frame);peer.outgoing.clear()
        return peer,request,probe

    def test_conflict_precedes_ACK_only_after_real_probe_and_query(self):
        peer,request,_=self.prepared()
        peer.receive(request)
        self.assertEqual(len(peer.outgoing),2)
        self.assertEqual((peer.outgoing[0][12:14],peer.outgoing[0][54]),(b'\x86\xdd',136))
        self.assertEqual(peer.outgoing[0][62:78],request[36:52])
        self.assertEqual(peer.outgoing[1][12:21],b'\x88\xc3IP6O'+bytes([0,request[19],1]))

    def test_metadata_without_actual_probe_cannot_release_conflict_or_ACK(self):
        peer,request,probe=self.prepared(drop_probe=True)
        self.assertIsNotNone(probe)
        peer.receive(request)
        self.assertEqual(peer.outgoing,[])
        self.assertIsNotNone(peer.pending)
        peer.receive(probe)
        self.assertEqual([frame[12:14] for frame in peer.outgoing],[b'\x86\xdd',b'\x88\xc3'])

    def test_wrong_raw_flags_and_duplicate_control_are_rejected(self):
        peer,request,_=self.prepared()
        changed=bytearray(request);struct.pack_into('!I',changed,24,0x940)
        with self.assertRaisesRegex(ValueError,'queried exact'):peer.receive(bytes(changed))
        self.assertEqual(peer.outgoing,[])
        peer.receive(request);peer.outgoing.clear()
        with self.assertRaisesRegex(ValueError,'ordered ownership'):peer.receive(request)

    def test_policy_is_selected_before_any_address_operation(self):
        hello=self.guest_prefix()[0]
        for retain in (False,True):
            with self.subTest(retain=retain):
                selected=bytearray(hello);selected[23]=int(retain)
                peer=Peer(0,'global',native=True,retain_routes=retain);peer.receive(bytes(selected))
                self.assertTrue(peer.ready)
                selected[23]=int(not retain)
                with self.assertRaisesRegex(ValueError,'pinned cleanup policy'):
                    Peer(0,'global',native=True,retain_routes=retain).receive(bytes(selected))

    def test_equal_monotonic_tick_is_valid_but_backward_tick_is_rejected(self):
        frames=self.guest_prefix();hello=frames[0]
        begin=next(frame for frame in frames if frame[12:14]==b'\x88\xc3' and frame[20]==1)
        tick=int.from_bytes(hello[52:60],'big')
        for delta in (0,-1):
            peer=Peer(0,'global');peer.receive(hello)
            changed=bytearray(begin);changed[52:60]=(tick+delta).to_bytes(8,'big')
            if delta:
                with self.assertRaisesRegex(ValueError,'monotonic'):peer.receive(bytes(changed))
            else:
                peer.receive(bytes(changed));self.assertEqual(peer.case,1)


if __name__=='__main__':unittest.main()
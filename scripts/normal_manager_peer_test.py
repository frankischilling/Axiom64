"""Check real client packet replay while a supervision ACK is deliberately held."""
import unittest
from manager_peer_test import acquired, frame
from normal_manager_test import SupervisionPeer


class HeldRestartAck(unittest.TestCase):
    def test_same_transaction_retries_remain_pending(self):
        peer = SupervisionPeer(0, True)
        old, new = bytes.fromhex('12345678'), bytes.fromhex('87654321')
        acquired(peer, old)
        peer.output.clear()
        peer.packet(frame(peer, new, 3, requested=True))
        peer.packet(frame(peer, new, 3, requested=True))
        self.assertEqual(peer.pending, new)
        self.assertEqual(peer.restart_transaction, new)
        self.assertEqual(peer.initial_transaction, old)
        self.assertFalse(peer.output)
        peer.approve()
        self.assertIsNone(peer.pending)
        self.assertEqual(peer.ack_server, peer.other)
        self.assertTrue(peer.output)
        peer.output.clear()
        peer.packet(frame(peer, new, 3, requested=True))
        self.assertIsNone(peer.pending)
        self.assertEqual(peer.restart_transaction, new)
        self.assertEqual(peer.ack_server, peer.other)
        self.assertTrue(peer.output)
        peer.output.clear()
        peer.packet(frame(peer, new, 7, configured=True, destination=peer.other, server=peer.other))
        peer.packet(frame(peer, bytes.fromhex('aabbccdd'), 1))
        self.assertFalse(peer.output)

    def test_different_pending_transaction_is_rejected(self):
        peer = SupervisionPeer(1, True)
        peer.packet(frame(peer, bytes.fromhex('12345678'), 3, requested=True))
        with self.assertRaises(RuntimeError):
            peer.packet(frame(peer, bytes.fromhex('87654321'), 3, requested=True))


if __name__ == '__main__':
    unittest.main(verbosity=2)

# SPDX-License-Identifier: GPL-3.0-or-later
"""Regress carrier fixture packet identity, timing gates and physical removal."""
import io
import unittest
from manager_link_hardware import Hardware
from manager_link_peer import LinkPeer
from manager_link_test import Controller
from manager_protocol_peer import fingerprint
from manager_protocol_peer_test import request, reply_options


def packet(peer, frame, milliseconds=0):
    peer.packet(frame)
    peer.receipt(len(frame), fingerprint(frame), milliseconds, 4)


def initial(peer, transaction=b'\x12\x34\x56\x78'):
    peer.offer_allowed = peer.ack_allowed = True
    packet(peer, request(peer, transaction))
    peer.tick(True, None)
    packet(peer, request(peer, transaction, kind=3, requested=True, server=peer.ip))
    peer.tick(True, None)


class Packets(unittest.TestCase):
    def test_uninstalled_ack_candidate_does_not_change_returned_configuration(self):
        peer = LinkPeer(0, 'carrier-probing', 0)
        initial(peer)
        peer.interrupt()
        peer.resume(False)
        packet(peer, request(peer, b'\x87\x65\x43\x21'))
        peer.tick(True, 10000)
        self.assertEqual(reply_options(bytes.fromhex(peer.sent[-1]['frame']))[54], peer.ip)
        packet(peer, request(peer, b'\x87\x65\x43\x21', kind=3, requested=True, server=peer.ip))
        peer.tick(True, 10000)
        options = reply_options(bytes.fromhex(peer.sent[-1]['frame']))
        self.assertEqual(options[1], b'\xff\xff\xff\0')
        self.assertEqual(options[6], bytes([10, 23, 1, 53]))

    def test_accepted_lease_revalidates_with_fresh_transaction_and_changed_ack(self):
        peer = LinkPeer(1, 'carrier-bound', 1)
        initial(peer)
        peer.interrupt()
        peer.resume(True)
        packet(peer, request(peer, b'\x87\x65\x43\x21', kind=3, requested=True))
        peer.tick(True, 10000)
        self.assertTrue(peer.saved_revalidation)
        options = reply_options(bytes.fromhex(peer.sent[-1]['frame']))
        self.assertEqual(options[54], peer.other)
        self.assertEqual(options[1], b'\xff\xff\xff\x80')
        self.assertEqual(options[6], bytes([10, 23, 2, 54]))

    def test_old_discover_is_rejected_after_real_carrier_return(self):
        peer = LinkPeer(0, 'carrier-selecting', 0)
        initial(peer)
        peer.interrupt()
        peer.resume(True)
        with self.assertRaisesRegex(RuntimeError, 'fresh transaction'):
            packet(peer, request(peer, b'\x12\x34\x56\x78'))

    def test_unaccepted_candidate_cannot_authorize_saved_address_reboot(self):
        peer = LinkPeer(0, 'carrier-probing', 0)
        initial(peer)
        peer.interrupt()
        peer.resume(False)
        with self.assertRaisesRegex(RuntimeError, 'retained accepted lease'):
            packet(peer, request(peer, b'\x87\x65\x43\x21', kind=3, requested=True))

    def test_healthy_renewal_ack_waits_for_packet_observed_after_withdrawal(self):
        peer = LinkPeer(1, 'carrier-bound', 0)
        initial(peer)
        transaction = b'\x87\x65\x43\x21'
        packet(peer, request(peer, transaction, kind=3, configured=True, destination=peer.ip), 20000)
        peer.tick(True, None)
        peer.tick(True, 20001)
        self.assertEqual(peer.acks, 1)
        packet(peer, request(peer, transaction, kind=3, configured=True, destination=peer.ip), 24000)
        peer.tick(True, 20001)
        self.assertEqual(peer.acks, 2)
        frame = bytes.fromhex(peer.sent[-1]['frame'])
        self.assertEqual(frame[52:54], bytes(2))
        self.assertEqual(frame[54:58], peer.address)

    def test_deferred_ack_echoes_its_original_request_context(self):
        peer = LinkPeer(1, 'carrier-bound', 0)
        transaction = b'\x12\x34\x56\x78'
        packet(peer, request(peer, transaction))
        peer.tick(True, None)
        packet(peer, request(peer, transaction, kind=3, requested=True, server=peer.ip))
        packet(peer, request(peer, b'\x87\x65\x43\x21', kind=3, configured=True,
                             destination=peer.ip), 20000)
        peer.tick(True, None)
        frame = bytes.fromhex(peer.sent[-1]['frame'])
        self.assertEqual(frame[52:54], b'\x80\0')
        self.assertEqual(frame[54:58], bytes(4))

    def test_duplicate_selected_request_does_not_approve_an_extra_ack(self):
        peer = LinkPeer(1, 'carrier-bound', 0)
        initial(peer)
        count = len(peer.sent)
        packet(peer, request(peer, b'\x12\x34\x56\x78', kind=3, requested=True, server=peer.ip))
        peer.tick(True, None)
        self.assertEqual((peer.acks, len(peer.sent)), (1, count))

    def test_static_and_disabled_profiles_cannot_silently_fall_back_to_dhcp(self):
        for scenario in ('static-bound', 'disabled', 'disabled-initial', 'disabled-failed'):
            with self.subTest(scenario=scenario):
                peer = LinkPeer(0, scenario, 0)
                with self.assertRaisesRegex(RuntimeError, 'never emits|never emits manager'):
                    packet(peer, request(peer, b'\x12\x34\x56\x78'))


class Monitor:
    def __init__(self):
        self.requests = []
        self.paused = False
        self.identities = {4: 0x10411af4, 5: 0x100e8086}

    def command(self, name, arguments=None):
        self.requests.append((name, arguments))
        if name in ('stop', 'cont'):
            self.paused = name == 'stop'
        if name == 'query-pci':
            return [dict(devices=[dict(slot=slot) for slot in self.identities])]


class Ports:
    def __init__(self, monitor):
        self.monitor, self.address = monitor, 0
        self.requests, self.response = [], None

    def write(self, data):
        assert self.monitor.paused
        request = data.decode().strip()
        self.requests.append(request)
        values = request.split()
        if values[:2] == ['outl', '0xcf8']:
            self.address = int(values[2], 0)
        elif values[:2] == ['outl', '0xae08']:
            mask = int(values[2], 0)
            for slot in tuple(self.monitor.identities):
                if mask & (1 << slot):
                    del self.monitor.identities[slot]
        response = 'OK'
        if values[:2] == ['inl', '0xcf8']:
            response += f' {self.address:#x}'
        elif values[:2] == ['inl', '0xcfc']:
            response += f' {self.monitor.identities.get((self.address >> 11) & 31, 0xffffffff):#x}'
        self.response = response.encode() + b'\n'

    def flush(self):
        pass

    def readline(self):
        return self.response


class PhysicalRemoval(unittest.TestCase):
    def hardware(self, affected, transport):
        hardware = Hardware.__new__(Hardware)
        hardware.monitor, hardware.affected, hardware.transport = Monitor(), affected, transport
        if transport == 'legacy':
            hardware.monitor.identities[4] = 0x10001af4
        hardware.stream, hardware.records = Ports(hardware.monitor), []
        return hardware

    def test_both_physical_slots_and_both_transports_require_actual_disappearance(self):
        for affected in (0, 1):
            for transport in ('modern', 'legacy'):
                with self.subTest(affected=affected, transport=transport):
                    hardware = self.hardware(affected, transport)
                    hardware.remove()
                    self.assertFalse(hardware.monitor.paused)
                    self.assertEqual(list(hardware.monitor.identities), [5 - affected])
                    self.assertIn(f'outl 0xae08 {1 << (affected + 4):#x}', hardware.stream.requests)
                    removal = next(row for row in hardware.records if row.get('operation') == 'remove')
                    self.assertEqual(removal['after'][affected], 0xffffffff)
                    self.assertEqual(hardware.stream.address, 0)

    def test_unexpected_healthy_identity_aborts_before_any_device_deletion(self):
        hardware = self.hardware(0, 'modern')
        hardware.monitor.identities[5] = 0xffffffff
        with self.assertRaisesRegex(RuntimeError, 'both real PCI identities'):
            hardware.remove()
        self.assertFalse(any(name == 'device_del' for name, _ in hardware.monitor.requests))
        self.assertFalse(hardware.monitor.paused)

    def test_fixture_rejects_virtual_clock_manipulation(self):
        hardware = self.hardware(0, 'modern')
        with self.assertRaisesRegex(RuntimeError, 'only hardware port'):
            hardware.io('clock_step 60000000000')
        self.assertEqual(hardware.stream.requests, [])


class GuestBarriers(unittest.TestCase):
    def controller(self, scenario='static-probing', affected=0):
        process = type('Process', (), {'stdin': io.BytesIO()})()
        peers = [LinkPeer(lane, scenario, affected) for lane in (0, 1)]
        hardware = type('Physical', (), {'carrier': lambda self, up: self.records.append(up)})()
        hardware.records = []
        return Controller(process, peers, affected, hardware, 'native', None)

    def test_probe_fault_does_not_wait_for_the_other_adapter_to_finish_binding(self):
        controller = self.controller()
        controller.ready = True
        controller.target.probes = 1
        controller.drive()
        self.assertEqual(controller.hardware.records, [False])
        self.assertTrue(controller.interrupted)
        self.assertIsNone(controller.pending)

    def test_unsolicited_completion_cannot_approve_an_observation(self):
        controller = self.controller()
        with self.assertRaisesRegex(RuntimeError, 'outstanding independent observation'):
            controller.line('MANAGER_LINK_PASS stage=down affected=0 monotonic_ms=12000')

    def test_wrong_adapter_permanent_error_cannot_validate_the_selected_failure(self):
        controller = self.controller('failed-bound')
        with self.assertRaisesRegex(RuntimeError, 'physically removed driver'):
            controller.line('MANAGER_LINK_DRIVER_FAILED index=2 errno=5 monotonic_ms=12000')
        self.assertEqual(controller.failures, [])
        controller.line('MANAGER_LINK_DRIVER_FAILED index=1 errno=5 monotonic_ms=12000')
        self.assertEqual(controller.failures, [dict(index=1, errno=5, guest_ms=12000)])


if __name__ == '__main__':
    unittest.main()

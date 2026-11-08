# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain exact ARP ownership when Linux probes through a surviving address."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv4_lifetimes.wire_packets import definitions
from ipv4_lifetimes.wire_trace import owned_arp


class LifetimeArp(unittest.TestCase):
    def setUp(self):
        # Actual native dynamic case 17: a neighbour retry after primary expiry.
        self.row = dict(index=1, monotonic_ns=2266561209504,
                        frame='ffffffffffff02000000000208060001080006040001020000000002c6125102000000000000c6125015')
        self.case = dict(spec=definitions()[17], events=[
            dict(phase='lifetime-start', monotonic_ns=2265504908511),
            dict(phase='end', monotonic_ns=2267523984054)])

    def test_recorded_native_survivor_owns_the_retry(self):
        owned_arp(self.row, [self.case], True)

    def test_both_lanes_and_both_survivor_policies_own_only_their_address(self):
        for spec in definitions():
            if spec['survival'] not in (1, 3):
                continue
            row = dict(self.row, index=spec['lane'])
            frame = bytearray.fromhex(row['frame'])
            hardware = bytes((2, 0, 0, 0, 0, spec['lane'] + 1))
            frame[6:12] = frame[22:28] = hardware
            other = spec['source'] + (256 if spec['survival'] == 1 else 1)
            frame[28:32] = other.to_bytes(4, 'big')
            frame[38:42] = spec['peer'].to_bytes(4, 'big')
            row['frame'] = frame.hex()
            case = dict(self.case, spec=spec)
            with self.subTest(spec=spec):
                owned_arp(row, [case], True)
                if spec['survival'] == 3:
                    case = dict(case, spec=dict(spec, survival=2))
                    with self.assertRaises(ValueError):
                        owned_arp(row, [case], True)

    def test_original_primary_owns_requests_without_survivor(self):
        frame = bytearray.fromhex(self.row['frame'])
        frame[28:32] = bytes.fromhex('c6125002')
        owned_arp(dict(self.row, frame=frame.hex()), [], False)

    def test_survivor_requires_native_capture(self):
        with self.assertRaises(ValueError):
            owned_arp(self.row, [self.case], False)

    def test_survivor_requires_its_recorded_case(self):
        with self.assertRaises(ValueError):
            owned_arp(self.row, [], True)

    def test_survivor_is_rejected_outside_the_case_interval(self):
        for tick in (2265504908511, 2267523984055):
            with self.subTest(tick=tick), self.assertRaises(ValueError):
                owned_arp(dict(self.row, monotonic_ns=tick), [self.case], True)

    def test_survivor_is_rejected_for_final_loss_or_cascade(self):
        for survival in (0, 2):
            case = copy.deepcopy(self.case)
            case['spec']['survival'] = survival
            with self.subTest(survival=survival), self.assertRaises(ValueError):
                owned_arp(self.row, [case], True)

    def test_unowned_addresses_hardware_and_target_remain_rejected(self):
        for offset, replacement in ((28, bytes.fromhex('c6124102')), (28, bytes.fromhex('c6125103')),
                                    (38, bytes.fromhex('c6125016')), (0, bytes.fromhex('020000000103')),
                                    (22, bytes.fromhex('020000000001'))):
            frame = bytearray.fromhex(self.row['frame'])
            frame[offset:offset + len(replacement)] = replacement
            with self.subTest(offset=offset, replacement=replacement.hex()), self.assertRaises(ValueError):
                owned_arp(dict(self.row, frame=frame.hex()), [self.case], True)


class LifetimeZeroArp(unittest.TestCase):
    def setUp(self):
        # Actual native dynamic case 7: original request and zero-source retry.
        self.original = dict(index=0, monotonic_ns=2277602825194,
            frame='ffffffffffff02000000000108060001080006040001020000000001c6124002000000000000c6124017')
        self.retry = dict(index=0, monotonic_ns=2278620271539,
            frame='ffffffffffff0200000000010806000108000604000102000000000100000000000000000000c6124017')
        self.case = dict(spec=definitions()[7], events=[
            dict(phase='lifetime-start', monotonic_ns=2277599608608),
            dict(phase='end', monotonic_ns=2279613328821)])

    def test_actual_native_zero_source_retry_retains_original_request_ownership(self):
        owned_arp(self.retry, [self.case], True, [self.original])

    def test_zero_source_is_not_a_guest_source(self):
        with self.assertRaises(ValueError):
            owned_arp(self.retry, [self.case], False, [self.original])

    def test_zero_source_requires_an_original_owned_request(self):
        for originals in ([], [dict(self.original, index=1)], [self.retry],
                          [dict(self.original, monotonic_ns=self.retry['monotonic_ns'] + 1)]):
            with self.subTest(originals=originals), self.assertRaises(ValueError):
                owned_arp(self.retry, [self.case], True, originals)

    def test_zero_source_requires_expiry_and_the_same_case_interval(self):
        for tick in (2277599608608, 2279613328822):
            with self.subTest(tick=tick), self.assertRaises(ValueError):
                owned_arp(dict(self.retry, monotonic_ns=tick), [self.case], True, [self.original])

    def test_zero_source_cannot_substitute_for_a_guard_or_stream(self):
        for change in (dict(transport=2), dict(peer=self.case['spec']['peer'] + 1)):
            case = dict(self.case, spec=dict(self.case['spec'], **change))
            with self.subTest(change=change), self.assertRaises(ValueError):
                owned_arp(self.retry, [case], True, [self.original])

    def test_zero_source_requires_the_same_request_bytes(self):
        for at in (0, 6, 22, 28, 32, 38):
            frame = bytearray.fromhex(self.original['frame'])
            frame[at] ^= 1
            with self.subTest(at=at), self.assertRaises(ValueError):
                owned_arp(self.retry, [self.case], True, [dict(self.original, frame=frame.hex())])


if __name__ == '__main__':
    unittest.main()

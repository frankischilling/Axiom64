# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay actual router packets and reject damaged fields, unions and clocks."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_router_capture import checksum, inspect, qemu_records

FIXTURES = Path(__file__).with_name('fixtures')


class RouterCapture(unittest.TestCase):
    def setUp(self):
        self.capture = FIXTURES / 'ipv6-router-bios-modern.pcap'
        self.serial = FIXTURES / 'ipv6-router-bios-modern.log'
        self.text = self.serial.read_text()
        self.metadata = json.loads((FIXTURES / 'ipv6-router-bios-modern.json').read_text())
        self.rows = list(qemu_records(self.capture))
        self.header = self.capture.read_bytes()[:24]

    def test_original_qemu_capture_and_source_epoch(self):
        self.assertEqual(hashlib.sha256(self.capture.read_bytes()).hexdigest(), self.metadata['capture_sha256'])
        self.assertEqual(hashlib.sha256(self.serial.read_bytes()).hexdigest(), self.metadata['serial_sha256'])
        self.assertEqual(struct.unpack_from('<I', self.header, 16)[0], 65536)
        proof = inspect(self.capture, 0, self.text)
        self.assertTrue(proof['passed'])
        self.assertEqual(proof['malformed_and_policy_cases'], list(range(9)))
        self.assertEqual(proof['generated_UDP_pairs'], 4)
        self.assertEqual(proof['replacement_states'], 6)
        self.assertEqual(proof['neighbor_retransmissions'], 2)
        self.assertEqual(proof['retransmit_milliseconds'], 2000)
        self.assertEqual(proof['routed_replies'], 2)
        self.assertEqual(proof['routed_reply_hop_limit'], 41)
        self.assertEqual(proof['valid_advertisements'], 13)
        self.assertEqual(proof['first_pio_states'], 12)
        self.assertEqual(self.metadata['router_phases'], 27)

    def test_first_pio_state_union_flags_lifetimes_and_prefix_ownership(self):
        line = next(line for line in self.text.splitlines()
                    if line.startswith('IPV6_ROUTER_FIRST_PIO lane=0 phase=zero kind=5 '))
        for damaged in (None, line.replace('flags=a2', 'flags=82'),
                        line.replace('valid=7200', 'valid=4294967295'),
                        line.replace('preferred=0', 'preferred=1'),
                        line.replace('kind=5', 'kind=6'),
                        line.replace('prefix_permanent=1', 'prefix_permanent=0'),
                        line.replace('IPV6_ROUTER_FIRST_PIO ', 'IPV6_ROUTER_FIRST_PIO_WAIT ')):
            text = self.text.replace(line + '\n', '' if damaged is None else damaged + '\n')
            self.assertNotEqual(text, self.text)
            self.rejected(text=text)

    def test_checksum_valid_first_zero_pio_damage(self):
        import ipaddress
        prefix = ipaddress.IPv6Address('2001:db8:40:5::').packed
        for field, relative, value in (('valid', 7, 1), ('autonomous', 3, 0x80),
                                        ('network', 23, 9)):
            rows = [dict(row) for row in self.rows]
            changed = False
            for row in rows:
                frame = bytearray(row['frame'])
                if len(frame) < 110 or frame[20] != 58 or frame[54] != 134:
                    continue
                at = 70
                while at + 2 <= len(frame) and frame[at] != 3:
                    size = frame[at + 1] * 8
                    if not size or at + size > len(frame):
                        break
                    at += size
                if at + 32 > len(frame) or frame[at] != 3 or frame[at + 16:at + 32] != prefix or any(frame[at + 4:at + 12]):
                    continue
                frame[at + relative] = value
                frame[56:58] = bytes(2)
                struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                    struct.pack('!I3xB', len(frame) - 54, 58) + bytes(frame[54:])))
                row['frame'] = bytes(frame)
                changed = True
                break
            self.assertTrue(changed, field)
            self.rejected(rows=rows)

    def write(self, path, rows):
        with path.open('wb') as stream:
            stream.write(self.header)
            for row in rows:
                seconds, micros = divmod(row['stamp'], 1000000)
                frame = row['frame']
                stream.write(struct.pack('<IIII', seconds, micros, len(frame), len(frame)))
                stream.write(frame)

    def rejected(self, rows=None, text=None, truncate=False, invalid_snapshot=False):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'damaged.pcap'
            self.write(path, rows if rows is not None else self.rows)
            if truncate:
                path.write_bytes(path.read_bytes()[:-1])
            if invalid_snapshot:
                data = bytearray(path.read_bytes())
                struct.pack_into('<I', data, 16, 65537)
                path.write_bytes(data)
            try:
                proof = inspect(path, 0, self.text if text is None else text)
                self.assertFalse(proof['passed'])
            except ValueError:
                pass

    def test_missing_original_packet_and_truncated_bytes(self):
        self.rejected(rows=self.rows[:-1])
        self.rejected(truncate=True)
        self.rejected(invalid_snapshot=True)

    def test_learned_hop_and_prefix_lifetime_damage(self):
        for kind in ('hops', 'lifetime'):
            rows = [dict(row) for row in self.rows]
            changed = False
            for row in rows:
                frame = bytearray(row['frame'])
                if kind == 'hops' and len(frame) >= 78 and frame[20] == 17 and frame[21] == 61:
                    frame[21] = 60
                elif kind == 'lifetime' and len(frame) > 110 and frame[20] == 58 and frame[54] == 134 and frame[58] == 61:
                    at = 70
                    while at < len(frame) and frame[at] != 3:
                        at += frame[at + 1] * 8
                    if at >= len(frame) or int.from_bytes(frame[at + 4:at + 8], 'big') != 8:
                        continue
                    frame[at + 7] = 7
                    frame[56:58] = bytes(2)
                    payload = frame[54:]
                    struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                        struct.pack('!I3xB', len(payload), 58) + bytes(payload)))
                else:
                    continue
                row['frame'] = bytes(frame)
                changed = True
                break
            self.assertTrue(changed, kind)
            self.rejected(rows=rows)

    def test_shortened_actual_expiry_and_missing_policy_observation(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            frame = row['frame']
            if frame[12:14] == b'\x88\xbf' and frame[19:21] == bytes([6, 0]):
                row['stamp'] -= 1000000
                break
        else:
            self.fail('actual finite-expiry request is missing')
        self.rejected(rows=rows)
        text = self.text.replace('IPV6_ROUTER_MAC_POLICY lane=0 installed=0\n', '')
        self.assertNotEqual(text, self.text)
        self.rejected(text=text)


    def test_replacement_metadata_and_missing_observation(self):
        line = next(line for line in self.text.splitlines()
                    if line.startswith('IPV6_ROUTER_REPLACEMENT lane=0 phase=zero '))
        for damaged in (None, line.replace('flags=a2', 'flags=22'),
                        line.replace('flags=a2', 'flags=82'),
                        line.replace('IPV6_ROUTER_REPLACEMENT ', 'IPV6_ROUTER_DEPRECATION_WAIT '),
                        line.replace('prefix_permanent=1', 'prefix_permanent=0'),
                        line.replace('prefix_routes=1', 'prefix_routes=2'),
                        line.replace('valid=7200', 'valid=4294967295')):
            text = self.text.replace(line + '\n', '' if damaged is None else damaged + '\n')
            self.assertNotEqual(text, self.text)
            self.rejected(text=text)

    def test_replacement_refresh_lifetime_damage(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            frame = bytearray(row['frame'])
            if len(frame) < 110 or frame[20] != 58 or frame[54] != 134 or frame[58] != 61:
                continue
            at = 70
            while at < len(frame) and frame[at] != 3:
                at += frame[at + 1] * 8
            if at >= len(frame) or int.from_bytes(frame[at + 4:at + 8], 'big') != 100:
                continue
            frame[at + 7] = 101
            frame[56:58] = bytes(2)
            payload = frame[54:]
            struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                struct.pack('!I3xB', len(payload), 58) + bytes(payload)))
            row['frame'] = bytes(frame)
            self.rejected(rows=rows)
            break
        else:
            self.fail('actual replacement refresh advertisement is missing')


    def test_recreated_address_requires_fresh_pio_lifetime_update(self):
        line = next(line for line in self.text.splitlines()
                    if line.startswith('IPV6_ROUTER_REPLACEMENT lane=0 phase=readd-zero '))
        for damaged in (None, line.replace('flags=a2', 'flags=82'),
                        line.replace('valid=7200', 'valid=4294967295')):
            text = self.text.replace(line + '\n', '' if damaged is None else damaged + '\n')
            self.assertNotEqual(text, self.text)
            self.rejected(text=text)

    def retry_indices(self, rows):
        indices = [index for index, row in enumerate(rows)
                   if len(row['frame']) >= 86 and row['frame'][6:12] == bytes.fromhex('525400123410')
                   and row['frame'][20] == 58 and row['frame'][54] == 135
                   and row['frame'][77] == 0x44]
        self.assertEqual(len(indices), 2)
        return indices

    def test_missing_neighbor_retry(self):
        rows = [dict(row) for row in self.rows]
        del rows[self.retry_indices(rows)[1]]
        self.rejected(rows=rows)

    def test_neighbor_retry_rejects_original_one_second_bug(self):
        rows = [dict(row) for row in self.rows]
        first, second = self.retry_indices(rows)
        self.assertGreaterEqual(rows[second]['stamp'] - rows[first]['stamp'], 1980000)
        rows[second]['stamp'] = rows[first]['stamp'] + 1000000
        self.rejected(rows=rows)

    def test_checksum_valid_advertised_neighbor_timer_damage(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            frame = bytearray(row['frame'])
            if (len(frame) < 86 or frame[20] != 58 or frame[54] != 134
                    or int.from_bytes(frame[66:70], 'big') != 2000):
                continue
            struct.pack_into('!I', frame, 66, 3000)
            frame[56:58] = bytes(2)
            payload = frame[54:]
            struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                struct.pack('!I3xB', len(payload), 58) + bytes(payload)))
            row['frame'] = bytes(frame)
            self.rejected(rows=rows)
            break
        else:
            self.fail('actual nonzero advertised neighbor timer is missing')

    def test_routed_reply_rejects_incoming_interface_hop_limit(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            frame = bytearray(row['frame'])
            if len(frame) < 78 or frame[6:12] != bytes.fromhex('525400123410') or frame[54] != 129:
                continue
            self.assertEqual(frame[21], 41)
            frame[21] = 51
            row['frame'] = bytes(frame)
            self.rejected(rows=rows)
            break
        else:
            self.fail('actual routed echo reply is missing')

    def test_routed_error_rejects_checksum_valid_changed_quote(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            frame = bytearray(row['frame'])
            if len(frame) < 126 or frame[6:12] != bytes.fromhex('525400123410') or frame[54:56] != b'\x01\x04':
                continue
            self.assertEqual(frame[69], 64)
            frame[69] = 63
            frame[56:58] = bytes(2)
            payload = frame[54:]
            struct.pack_into('!H', frame, 56, checksum(bytes(frame[22:54]) +
                struct.pack('!I3xB', len(payload), 58) + bytes(payload)))
            row['frame'] = bytes(frame)
            self.rejected(rows=rows)
            break
        else:
            self.fail('actual routed port-error quote is missing')

    def test_missing_routed_echo_reply(self):
        rows = [dict(row) for row in self.rows]
        for index, row in enumerate(rows):
            frame = row['frame']
            if len(frame) >= 78 and frame[6:12] == bytes.fromhex('525400123410') and frame[54] == 129:
                del rows[index]
                self.rejected(rows=rows)
                break
        else:
            self.fail('actual routed echo reply is missing')


if __name__ == '__main__':
    unittest.main()

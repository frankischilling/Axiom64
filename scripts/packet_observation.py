# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe complete original QEMU capture records without changing packet clocks."""
import hashlib
import json
from pathlib import Path
import struct
import time


class PcapObservation:
    def __init__(self, path):
        self.path = Path(path)
        self.offset = 24
        self.header = None
        self.pending = False
        self.record = 0

    def watch(self, frame):
        if self.pending:
            raise ValueError('one pending independently observed input per capture')
        expected = bytes(frame)
        if not 14 <= len(expected) <= 65536:
            raise ValueError('bounded complete observed Ethernet input')
        first = self.path.stat().st_size if self.path.exists() else 0
        self.pending = True
        result = None

        def observed():
            nonlocal result
            if result is not None:
                return result
            try:
                source = self.path.open('rb')
            except FileNotFoundError:
                return None
            with source:
                header = source.read(24)
                if len(header) < 24:
                    return None
                if header[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
                    raise ValueError('original microsecond PCAP observation header')
                endian = '<' if header[:4] == b'\xd4\xc3\xb2\xa1' else '>'
                major, minor, _, _, snap, link = struct.unpack_from(endian + 'HHIIII', header, 4)
                if (major, minor, link) != (2, 4, 1) or not 14 <= snap <= 65536:
                    raise ValueError('bounded original Ethernet capture format')
                if self.header is not None and header != self.header:
                    raise ValueError('capture header changed during input observation')
                self.header = header
                source.seek(self.offset)
                while True:
                    at = source.tell()
                    packet = source.read(16)
                    if len(packet) < 16:
                        return None
                    seconds, micros, length, original = struct.unpack(endian + 'IIII', packet)
                    if micros >= 1000000 or not 14 <= length == original <= snap:
                        raise ValueError('complete original observed packet bounds')
                    actual = source.read(length)
                    if len(actual) < length:
                        return None
                    self.offset = source.tell()
                    self.record += 1
                    if at < first or actual != expected:
                        continue
                    receipt = time.monotonic_ns()
                    result = receipt / 1e9
                    self.pending = False
                    proof = dict(record=self.record - 1, sha256=hashlib.sha256(actual).hexdigest(),
                                 pcap_timestamp_us=seconds * 1000000 + micros,
                                 receipt_monotonic_ns=receipt, original_packet_times_not_rescaled=True)
                    with self.path.with_suffix('.observations.jsonl').open('a') as output:
                        output.write(json.dumps(proof) + '\n')
                    return result
        return observed

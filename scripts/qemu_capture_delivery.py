# SPDX-License-Identifier: GPL-3.0-or-later
"""Wait for complete original frames recorded on selected QEMU adapters."""
from pathlib import Path
import hashlib
import os
import struct


def _require(value, reason):
    if not value:
        raise ValueError(reason)


class Capture:
    def __init__(self, path):
        self.path = Path(path)
        self.identity = None
        self.offset, self.count = 0, 0
        self.endian, self.snap = None, None
        self.frames = {}

    def receipt(self, frame):
        _require(isinstance(frame, bytes) and 14 <= len(frame) <= 1518,
                'bounded original Ethernet delivery request')
        try:
            stream = self.path.open('rb')
        except FileNotFoundError:
            _require(self.identity is None, 'delivery capture disappeared')
            return None
        with stream:
            state = os.fstat(stream.fileno())
            identity = (state.st_dev, state.st_ino)
            _require(self.identity is None or self.identity == identity,
                    'delivery capture was replaced')
            _require(state.st_size >= self.offset, 'delivery capture was truncated')
            if self.endian is None:
                header = stream.read(24)
                if len(header) < 24:
                    return None
                _require(header[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'),
                        'original delivery capture magic')
                self.endian = '<' if header[:4] == b'\xd4\xc3\xb2\xa1' else '>'
                major, minor, _, _, self.snap, link = struct.unpack_from(self.endian + 'HHIIII', header, 4)
                _require((major, minor, link) == (2, 4, 1) and 1514 <= self.snap <= 65536,
                        'original delivery Ethernet capture format')
                self.identity, self.offset = identity, 24
            stream.seek(self.offset)
            while True:
                header = stream.read(16)
                if len(header) < 16:
                    break
                seconds, micros, size, original = struct.unpack(self.endian + 'IIII', header)
                _require(micros < 1000000 and 14 <= size == original <= min(self.snap, 1518),
                        'complete bounded original delivery record')
                data = stream.read(size)
                if len(data) < size:
                    break
                _require(self.count < 4096, 'bounded physical delivery frame count')
                digest = hashlib.sha256(data).hexdigest()
                self.frames.setdefault(digest, dict(record=self.count, packet_microseconds=seconds * 1000000 + micros,
                                           sha256=digest, bytes=size))
                self.offset += 16 + size
                self.count += 1
        receipt = self.frames.get(hashlib.sha256(frame).hexdigest())
        return dict(receipt) if receipt else None


class Delivery:
    def __init__(self, directory):
        self.captures = [Capture(Path(directory) / f'lane{lane}.pcap') for lane in range(2)]

    def receipt(self, lane, frame):
        _require(lane in (0, 1), 'selected physical delivery adapter')
        result = self.captures[lane].receipt(frame)
        return dict(physical=lane, **result) if result else None

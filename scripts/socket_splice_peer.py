# SPDX-License-Identifier: GPL-3.0-or-later
"""Check packet splice over real emulated Ethernet transmit and receive paths."""

from contextlib import ExitStack
import socket
import struct
import subprocess
import time

from ipv4_expiry_capture import read_capture
from tcp_fixture_inputs import digest


PROTOCOL = b'\x88\xb5'


def endpoints(lane):
    return bytes([0x52, 0x54, 0, 0x44, 0x53, lane]), bytes([2, 0x9a, 0x58, 0x4d, 0x64, lane])


def request(lane, sequence):
    guest, peer = endpoints(lane)
    return peer + guest + PROTOCOL + bytes(0x40 + lane + sequence * 7 + index for index in range(50))


def reply(frame):
    return frame[6:12] + frame[:6] + PROTOCOL + bytes(value ^ 0x80 for value in frame[14:])


def receive(channel, length, deadline):
    data = bytearray()
    while len(data) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('packet splice peer deadline')
        channel.settimeout(remaining)
        chunk = channel.recv(length - len(data))
        if not chunk:
            raise RuntimeError('guest exited before completing packet splice')
        data.extend(chunk)
    return bytes(data)


def exchange(channel, lane, deadline):
    expected = []
    for sequence in range(2):
        outgoing = request(lane, sequence)
        while True:
            length, = struct.unpack('!I', receive(channel, 4, deadline))
            if not 14 <= length <= 65536:
                raise RuntimeError('invalid packet splice Ethernet record length')
            frame = receive(channel, length, deadline)
            if frame[12:14] == PROTOCOL:
                break
        if frame != outgoing:
            raise RuntimeError(f'guest packet splice sent different bytes on NIC {lane}')
        incoming = reply(frame)
        channel.sendall(struct.pack('!I', len(incoming)) + incoming)
        expected.extend([outgoing, incoming])
    return expected


def run(command, log, output):
    command = list(command)
    clients, backends, captures = [], [], []
    deadline = time.monotonic() + 90
    with ExitStack() as resources:
        for lane, model in enumerate(('virtio-net-pci', 'e1000')):
            client, backend = socket.socketpair()
            clients.append(resources.enter_context(client))
            backends.append(resources.enter_context(backend))
            capture = log.with_name(f'{log.stem}-packet-{lane}.pcap')
            captures.append(capture)
            guest, _ = endpoints(lane)
            device = f'{model},netdev=packet{lane},addr={4 + lane},mac={guest.hex(":")}'
            if lane == 0:
                device += ',disable-legacy=on'
            command += ['-netdev', f'socket,id=packet{lane},fd={backend.fileno()}',
                        '-device', device, '-object',
                        f'filter-dump,id=cap{lane},netdev=packet{lane},file={capture}']
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                   stderr=subprocess.STDOUT,
                                   pass_fds=tuple(backend.fileno() for backend in backends))
        try:
            for backend in backends:
                backend.close()
            expected = [exchange(client, lane, deadline) for lane, client in enumerate(clients)]
            returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    proofs = []
    for capture, frames in zip(captures, expected):
        actual = [row['frame'] for row in read_capture(capture)
                  if row['frame'][12:14] == PROTOCOL]
        if actual != frames:
            raise RuntimeError(f'packet splice capture differs from the original exchange in {capture}')
        proofs.append(dict(path=capture.name, sha256=digest(capture), frames=len(actual)))
    return returncode, proofs

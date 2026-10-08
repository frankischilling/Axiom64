#!/usr/bin/env python3
"""Validate IPv4 wire packets against independent, isolated Ethernet peers."""
import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import time
from fetch import ROOT
from network_test import fixture
from ipv4_fault import expire, hold_arp_reply
from network_fault import inject
from qmp import Qmp


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def ipv4(source, destination, payload, protocol=1, identifier=0x6064):
    header = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload),
                                  identifier, 0, 51, protocol, 0, source, destination))
    struct.pack_into('!H', header, 10, checksum(bytes(header)))
    return bytes(header) + payload


class Peer:
    def __init__(self, lane):
        self.guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
        self.mac = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
        self.guest_ip = bytes([10, 23, lane + 1, 2])
        self.ip = bytes([10, 23, lane + 1, 1])
        self.targets = [self.ip, self.ip] + ([bytes([172, 19, 0, 4]), bytes([10, 99, 1, 1]),
                                    bytes([10, 99, 1, 1])] if lane == 0 else
                                   [bytes([10, 99, 1, 1]), bytes([10, 99, 1, 1])]) + [self.ip] * 3
        self.arp = self.echo = self.foreign = 0
        self.connection = None
        self.input = bytearray()
        self.output = bytearray()
        self.delayed = []
        self.arp_valid = False
        self.bad_arp = self.bad_ip = 0
        self.pressure = 0
        self.pressure_arp = 0
        self.pressure_reply = None
        self.missing_arp = []
        self.error_reply = None
        self.error_tests = 0
        self.incoming = False
        self.host_echo = self.protocol_error = 0
        self.unknown = self.host_request = None
        self.lane = lane
        self.cache_ack = False
        self.cache_arp = 0
        self.broadcast = 0
        self.lifetime = 0
        self.alias_arp = {}
        self.alias_echo = 0
        self.alias_refreshed = False
        self.alias_reply = 0
        self.reply_pressure_started = False
        self.held_replies = 0
        self.reply_ingress = 0

    @staticmethod
    def alias_address(sequence):
        return sequence + 10 + (sequence >= 89) if sequence < 129 else 10 if sequence == 130 else 139

    def alias_mac(self, last, refreshed=False):
        return bytes([2, 0x41, 0x58, self.lane, 2 if refreshed else 1, last])

    def arp_frame(self, operation, sender, mac):
        return (self.guest + mac + b'\x08\x06' +
                struct.pack('!HHBBH', 1, 0x0800, 6, 4, operation) + mac + sender +
                (self.guest if operation == 2 else b'\0' * 6) + self.guest_ip).ljust(60, b'\0')

    def refresh_alias(self):
        if not self.alias_refreshed:
            self.alias_refreshed = True
            self.queue(self.arp_frame(1, self.ip[:3] + b'\x8b', self.alias_mac(139, True)))

    def acknowledge_reply_pressure(self, phase):
        payload = bytearray(b'\0\0\0\0A' + phase + b'\0' + bytes([self.lane + 1]) +
                            bytes((i * 17) & 255 for i in range(8, 64)))
        struct.pack_into('!H', payload, 2, checksum(bytes(payload)))
        self.queue(self.ethernet(ipv4(self.ip, self.guest_ip, bytes(payload))))

    def reply_pressure(self):
        if not self.reply_pressure_started:
            self.reply_pressure_started = True
            self.reply_pressure_batch(0)

    def reply_pressure_batch(self, received):
        if received != self.reply_ingress:
            return
        if received == 96:
            self.acknowledge_reply_pressure(b'P')
            self.reply_ingress += 1
            return
        # One valid request followed by invalid opcodes reuses a whole hardware
        # RX ring while the original reply remains under controlled EAGAIN.
        # The guest acknowledges each batch, so every reuse reaches the stack.
        for offset in range(received, received + 8):
            last = offset + 140
            self.queue(self.arp_frame(3 if offset else 1, self.ip[:3] + bytes([last]),
                                      self.alias_mac(last)))
        self.reply_ingress += 8

    def alias_packet(self, frame):
        packet, sequence = frame[14:], self.alias_echo
        last = self.alias_address(sequence)
        mac = self.alias_mac(last, sequence == 131)
        if (sequence >= 132 or frame[:6] != mac or packet[0:2] != b'\x45\0' or
                int.from_bytes(packet[2:4], 'big') != 84 or len(packet) != 84 or
                packet[6:10] != b'\x40\0\x40\x01' or checksum(packet[:20]) or
                packet[12:16] != self.guest_ip or packet[16:20] != self.ip[:3] + bytes([last])):
            raise RuntimeError('ARP cache replacement destination MAC or IPv4 header differs')
        payload = packet[20:]
        if (payload[:2] != b'\x08\0' or checksum(payload) or
                payload[4:8] != b'CR' + struct.pack('!H', sequence) or
                payload[8:] != bytes((i * 17) & 255 for i in range(8, 64))):
            raise RuntimeError('ARP cache replacement payload differs')
        expected = 2 if sequence == 130 else 1
        if self.alias_arp.get(last, 0) != expected or (sequence == 131 and not self.alias_refreshed):
            raise RuntimeError('ARP eviction or reachable/refreshed cache lookup differs')
        reply = bytearray(payload)
        reply[0] = 0
        reply[2:4] = b'\0\0'
        struct.pack_into('!H', reply, 2, checksum(bytes(reply)))
        self.queue(self.guest + mac + b'\x08\x00' + ipv4(packet[16:20], self.guest_ip, bytes(reply)))
        self.alias_echo += 1

    def queue(self, frame):
        self.output.extend(struct.pack('!I', len(frame)) + frame)

    def release(self):
        now = time.monotonic()
        while self.delayed and self.delayed[0][0] <= now:
            _, frame = self.delayed.pop(0)
            self.arp_valid = True
            self.queue(frame)

    def release_pressure(self):
        if self.pressure_reply:
            self.queue(self.pressure_reply)
            self.pressure_reply = None

    def release_error(self):
        if self.error_reply:
            self.queue(self.error_reply)
            self.error_reply = None

    def acknowledge_expiry(self):
        payload = bytearray(b'\0\0\0\0EX\0' + bytes([self.lane + 1]) +
                            bytes((i * 17) & 255 for i in range(8, 64)))
        struct.pack_into('!H', payload, 2, checksum(bytes(payload)))
        self.cache_ack = True
        self.queue(self.ethernet(ipv4(self.ip, self.guest_ip, bytes(payload))))

    def ethernet(self, packet, broadcast=False):
        return ((b'\xff' * 6 if broadcast else self.guest) + self.mac + b'\x08\x00' + packet).ljust(60, b'\0')

    def error_packet(self, quote):
        payload = bytearray(struct.pack('!BBHHH', 3, 4, 0, 0, 1400) + quote)
        struct.pack_into('!H', payload, 2, checksum(bytes(payload)))
        return self.ethernet(ipv4(self.ip, self.guest_ip, bytes(payload)))

    def bad_quotes(self, packet):
        quote = packet[:28]
        fields = [(9, b'\x06'), (12, bytes([10, 23, (self.lane ^ 1) + 1, 2])),
                  (16, self.ip[:3] + b'\x44'), (2, b'\0\x13'), (6, b'\x20\0')]
        for offset, value in fields:
            bad = bytearray(quote)
            bad[offset:offset + len(value)] = value
            bad[10:12] = b'\0\0'
            struct.pack_into('!H', bad, 10, checksum(bytes(bad[:20])))
            self.queue(self.error_packet(bytes(bad)))
        bad = bytearray(quote)
        bad[10] ^= 1
        self.queue(self.error_packet(bytes(bad)))
        self.error_reply = self.error_packet(quote)
        self.error_tests += 1

    def inject_input(self):
        if self.incoming:
            return
        self.incoming = True
        payload = bytearray(b'\x08\0\0\0HI\0' + bytes([self.lane]) +
                            bytes((i * 11 + self.lane) & 255 for i in range(8, 64)))
        struct.pack_into('!H', payload, 2, checksum(bytes(payload)))
        self.host_request = bytes(payload)
        self.queue(self.ethernet(ipv4(self.ip, self.guest_ip, self.host_request)))
        self.unknown = ipv4(self.ip, self.guest_ip, b'UNKNOWN!', protocol=99)
        self.queue(self.ethernet(self.unknown))
        self.queue(self.ethernet(self.unknown, broadcast=True))
        self.queue(self.ethernet(ipv4(self.ip, self.guest_ip[:3] + b'\xff', b'UNKNOWN!', protocol=99)))
        # An ICMP error must not generate another ICMP error.
        self.queue(self.error_packet(ipv4(self.guest_ip, self.ip, self.host_request)[:28]))

    def arp_faults(self, valid):
        self.queue(valid[:41])
        self.bad_arp += 1
        # Every poisoned reply has a distinct, otherwise valid unicast MAC.
        # If any malformed reply resolves the neighbor, the subsequent IPv4
        # transmission precedes the delayed valid reply and fails this test.
        candidate = bytearray(valid)
        candidate[6:12] = candidate[22:28] = bytes.fromhex('02aabbccddee')
        fields = [(14, b'\0\x02'), (16, b'\x86\xdd'), (18, b'\x05'),
                  (19, b'\x10'), (20, b'\0\x03'), (22, b'\0' * 6),
                  (22, bytes.fromhex('01aabbccddee')), (28, bytes([127, 0, 0, 1])),
                  (32, b'\0' * 6), (28, self.guest_ip)]
        for offset, value in fields:
            bad = bytearray(candidate)
            bad[offset:offset + len(value)] = value
            self.queue(bytes(bad))
            self.bad_arp += 1

    def ip_faults(self, valid):
        packet = valid[14:]
        fields = [(0, b'\x65'), (0, b'\x46'), (2, b'\0\x13'), (2, b'\xff\xff'),
                  (8, b'\0'), (6, b'\x20\0'), (6, b'\0\x01'), (6, b'\x80\0'),
                  (12, b'\0' * 4), (12, bytes([127, 0, 0, 1])),
                  (12, bytes([224, 0, 0, 1])), (12, self.guest_ip[:3] + b'\xff'),
                  (16, bytes([10, 55, 0, 2]))]
        for offset, value in fields:
            bad = bytearray(packet)
            bad[offset:offset + len(value)] = value
            bad[10:12] = b'\0\0'
            struct.pack_into('!H', bad, 10, checksum(bytes(bad[:20])))
            self.queue(valid[:14] + bytes(bad))
            self.bad_ip += 1
        for offset in [10, 22]:
            bad = bytearray(valid)
            bad[14 + offset] ^= 1
            self.queue(bytes(bad))
            self.bad_ip += 1

    def packet(self, frame):
        if frame[6:12] != self.guest:
            raise RuntimeError('unexpected guest source MAC')
        if frame[12:14] == b'\x08\x06':
            if len(frame) < 42 or frame[28:32] != self.guest_ip:
                self.foreign += 1
                return
            target = frame[38:42]
            if frame[20:22] == b'\0\x02':
                last = 140 if self.reply_pressure_started else 139
                mac = self.alias_mac(last, not self.reply_pressure_started)
                expected = mac + self.guest + b'\x08\x06' + struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) + self.guest + self.guest_ip + mac + self.ip[:3] + bytes([last]) + b'\0' * 18
                if frame != expected or (not self.reply_pressure_started and not self.alias_refreshed):
                    raise RuntimeError('queued ARP reply destination, payload, order, or ownership differs')
                if self.reply_pressure_started:
                    self.held_replies += 1
                    if self.held_replies > 1:
                        raise RuntimeError('ARP reply output exceeds the bounded queue')
                    if self.held_replies == 1:
                        self.acknowledge_reply_pressure(b'Q')
                else:
                    self.alias_reply += 1
                return
            expected = b'\xff' * 6 + self.guest + b'\x08\x06' + \
                struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + self.guest + \
                self.guest_ip + b'\0' * 6 + target + b'\0' * 18
            if frame != expected:
                raise RuntimeError('ARP request fields or padding differ')
            if target[:3] == self.ip[:3] and 10 <= target[3] <= 139 and target[3] != 99:
                last = target[3]
                wanted = self.alias_address(self.alias_echo) if self.alias_echo < 129 or self.alias_echo == 130 else None
                if last != wanted:
                    raise RuntimeError('ARP replacement resolved an unexpected or still reachable peer')
                self.alias_arp[last] = self.alias_arp.get(last, 0) + 1
                self.queue(self.arp_frame(2, target, self.alias_mac(last)))
                return
            if target == self.ip[:3] + b'\x03':
                self.pressure_arp += 1
                self.pressure_reply = self.guest + self.mac + b'\x08\x06' + \
                    struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) + self.mac + \
                    target + self.guest + self.guest_ip + b'\0' * 18
                return
            if target == self.ip[:3] + b'\x63':
                self.missing_arp.append(time.monotonic())
                return
            if target != self.ip:
                raise RuntimeError('unexpected ARP next hop')
            if self.cache_ack and not self.cache_arp:
                self.cache_arp += 1
            self.arp += 1
            response = self.guest + self.mac + b'\x08\x06' + \
                struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) + self.mac + \
                self.ip + self.guest + self.guest_ip + b'\0' * 18
            if self.arp == 2:
                self.arp_valid = False
                self.arp_faults(response)
                self.delayed.append((time.monotonic() + .2, response))
                return
            self.arp_valid = True
        elif frame[12:14] == b'\x08\x00':
            if len(frame) < 34 or frame[26:30] != self.guest_ip:
                self.foreign += 1
                return
            packet = frame[14:]
            if packet[24:26] == b'CR':
                self.alias_packet(frame)
                return
            if self.cache_ack and not self.cache_arp:
                raise RuntimeError('expired ARP entry was used without resolving it again')
            if not self.arp_valid:
                raise RuntimeError('malformed ARP reply resolved the pending neighbor')
            length = int.from_bytes(packet[2:4], 'big')
            pressure = packet[24:26] == b'PR'
            errors = packet[24:26] == b'ER'
            reply = packet[20] == 0
            unreachable = packet[20:22] == b'\x03\x02'
            broadcast = packet[24:26] == b'BC'
            lifetime = packet[24:26] == b'LR'
            target = b'\xff' * 4 if broadcast else self.ip[:3] + b'\x03' if pressure else self.ip if errors or reply or unreachable or lifetime else (
                self.targets[self.echo] if self.echo < len(self.targets) else None)
            if (frame[:6] != (b'\xff' * 6 if broadcast else self.mac) or packet[0] != 0x45 or packet[1] != 0 or
                    length != len(packet) or checksum(packet[:20]) or packet[8] != 64 or
                    packet[9] != 1 or packet[6:8] != b'\x40\0' or packet[16:20] != target):
                raise RuntimeError('IPv4 header, route, length, TTL, or checksum differs')
            payload = packet[20:]
            if unreachable:
                if self.unknown is None or len(payload) != 36 or checksum(payload) or payload[4:8] != b'\0' * 4 or payload[8:] != self.unknown[:28]:
                    raise RuntimeError('ICMP protocol error checksum or exact quoted bytes differ')
                self.protocol_error += 1
                return
            if reply:
                if self.host_request is None or checksum(payload) or payload[1] or payload[4:] != self.host_request[4:]:
                    raise RuntimeError('kernel ICMP echo reply payload differs')
                self.host_echo += 1
                return
            if len(payload) < 8 or payload[:2] != b'\x08\0' or checksum(payload):
                raise RuntimeError('invalid ICMP echo request')
            if pressure:
                sequence = int.from_bytes(payload[6:8], 'big')
                expected = bytes((i * 17 + sequence) & 255 for i in range(8, 64))
                if len(payload) != 64 or sequence != self.pressure or payload[8:] != expected:
                    raise RuntimeError('queued raw sender payload, interface, sequence, or ownership differs')
                self.pressure += 1
                return
            if errors:
                self.bad_quotes(packet)
                return
            if broadcast:
                if len(payload) != 64 or payload[4:8] != b'BC\0\x01' or payload[8:] != bytes((i * 17) & 255 for i in range(8, 64)):
                    raise RuntimeError('broadcast ICMP bytes differ')
                self.broadcast += 1
                return
            if self.echo == 0:
                expected = b'\x43\x21\0\x01' + bytes((i * 17) & 255 for i in range(8, 64))
                if len(payload) != 64 or payload[4:] != expected:
                    raise RuntimeError('deterministic ICMP payload differs')
            reply = bytearray(payload)
            reply[0] = 0
            reply[2:4] = b'\0\0'
            struct.pack_into('!H', reply, 2, checksum(bytes(reply)))
            response = self.guest + self.mac + b'\x08\x00' + ipv4(packet[16:20], self.guest_ip, bytes(reply))
            if lifetime:
                expected = b'LR\0\x01' + bytes((i * 17) & 255 for i in range(8, 64))
                if len(payload) != 64 or payload[4:] != expected:
                    raise RuntimeError('retained receiver wake packet differs')
                self.lifetime += 1
                self.queue(response)
                return
            if self.echo == 0:
                self.ip_faults(response)
            self.echo += 1
        else:
            self.foreign += 1
            return
        self.queue(response)


def run(firmware, transport, timeout, fault=False):
    label = f'ipv4-{firmware}-{transport}' + ('-fault' if fault else '')
    log = ROOT / 'build' / (label + '.log')
    selector = selectors.DefaultSelector()
    debuggers = {}
    fault_debugger = fault_log = None
    control = Path('/tmp') / f'axiom64-ipv4-{os.getpid()}.sock'
    control.unlink(missing_ok=True)
    link_events = set()
    reply_debuggers = {}
    armed = Path('/tmp') / f'axiom64-ipv4-{os.getpid()}.armed'
    armed.unlink(missing_ok=True)
    servers, peers = [], [Peer(lane) for lane in range(2)]
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(ROOT / 'build/ipv4-test.iso'), '-nic', 'none', '-display', 'none',
               '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-qmp', f'unix:{control},server=on,wait=off',
               '-gdb', 'tcp:127.0.0.1:1237',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    for lane, model in enumerate(['virtio-net-pci', 'e1000']):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.setblocking(False)
        servers.append(server)
        selector.register(server, selectors.EVENT_READ, ('server', lane))
        nic = f'{model},netdev=peer{lane},id=nic{lane},addr={lane + 4:x},mac={peers[lane].guest.hex(":")}'
        if lane == 0:
            nic += ',disable-legacy=on' if transport == 'modern' else ',disable-modern=on'
        command += ['-netdev', f'socket,id=peer{lane},connect=127.0.0.1:{server.getsockname()[1]}',
                    '-device', nic]
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started, timed_out, error = time.monotonic(), False, None
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    timed_out = True
                    break
                tail = log.read_text(errors='replace')
                if fault and fault_debugger is None and 'IPV4_FAULT_READY' in tail:
                    fault_debugger, fault_log = inject('virtio', 'id', 1237, label, armed)
                if fault_debugger is not None and fault_debugger.poll() not in [None, 0]:
                    raise RuntimeError('raw socket device fault injection failed: ' + fault_log.read_text(errors='replace'))
                sending = not fault or armed.exists()
                for lane, peer in enumerate(peers):
                    if f'IPV4_ARP_REPLY_READY index={lane + 1}' in tail and lane not in reply_debuggers:
                        reply_armed = control.with_suffix(f'.reply-{lane + 1}.armed')
                        reply_released = control.with_suffix(f'.reply-{lane + 1}.released')
                        reply_armed.unlink(missing_ok=True)
                        reply_released.unlink(missing_ok=True)
                        debugger, debug_log = hold_arp_reply(lane + 1, 1237, label, reply_armed, reply_released)
                        reply_debuggers[lane] = (debugger, debug_log, reply_armed, reply_released)
                    if lane in reply_debuggers:
                        debugger, debug_log, reply_armed, reply_released = reply_debuggers[lane]
                        if debugger.poll() not in [None, 0]:
                            raise RuntimeError('ARP reply backpressure injection failed: ' + debug_log.read_text(errors='replace'))
                        if reply_armed.exists():
                            peer.reply_pressure()
                        for received in range(8, 97, 8):
                            if f'IPV4_ARP_REPLY_RX index={lane + 1} frames={received}\n' in tail:
                                peer.reply_pressure_batch(received)
                        if f'IPV4_ARP_REPLY_RELEASE index={lane + 1}' in tail:
                            reply_released.touch()
                    for stage, up in [('DOWN', False), ('UP', True)]:
                        event = f'IPV4_LINK_{stage} index={lane + 1}'
                        if event in tail and event not in link_events:
                            monitor = Qmp(control)
                            try:
                                monitor.command('set_link', {'name': f'nic{lane}', 'up': up})
                            finally:
                                monitor.close()
                            link_events.add(event)
                    if f'IPV4_CACHE_EXPIRY_READY index={lane + 1}' in tail and lane not in debuggers:
                        debuggers[lane] = expire(lane + 1, 1237, label)
                    if lane in debuggers and not peer.cache_ack:
                        debugger, debug_log = debuggers[lane]
                        if debugger.poll() is not None:
                            if debugger.returncode or f'IPV4_CACHE_EXPIRED index={lane + 1}' not in debug_log.read_text(errors='replace'):
                                raise RuntimeError('ARP cache expiration injection failed: ' + debug_log.read_text(errors='replace'))
                            peer.acknowledge_expiry()
                    peer.release()
                    if f'IPV4_PRESSURE_RELEASE index={lane + 1}' in tail:
                        peer.release_pressure()
                    if f'IPV4_ICMP_ERROR_RELEASE index={lane + 1}' in tail:
                        peer.release_error()
                    if f'IPV4_INPUT_READY index={lane + 1}' in tail:
                        peer.inject_input()
                    if f'IPV4_CACHE_REFRESH_READY index={lane + 1}' in tail:
                        peer.refresh_alias()
                    if peer.connection and peer.output and sending and peer.connection.fileno() in selector.get_map():
                        selector.modify(peer.connection, selectors.EVENT_READ | selectors.EVENT_WRITE,
                                        ('peer', lane))
                for key, events in selector.select(.01):
                    kind, lane = key.data
                    peer = peers[lane]
                    if kind == 'server':
                        connection, _ = key.fileobj.accept()
                        connection.setblocking(False)
                        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        peer.connection = connection
                        selector.unregister(key.fileobj)
                        selector.register(connection, selectors.EVENT_READ, ('peer', lane))
                        continue
                    connection = key.fileobj
                    if events & selectors.EVENT_READ:
                        data = connection.recv(65536)
                        if not data:
                            selector.unregister(connection)
                            continue
                        peer.input.extend(data)
                        while len(peer.input) >= 4:
                            length = int.from_bytes(peer.input[:4], 'big')
                            if length < 14 or length > 65553:
                                raise RuntimeError('invalid QEMU Ethernet length prefix')
                            if len(peer.input) < length + 4:
                                break
                            peer.packet(bytes(peer.input[4:length + 4]))
                            del peer.input[:length + 4]
                    if peer.output and sending:
                        try:
                            sent = connection.send(peer.output)
                            del peer.output[:sent]
                        except BlockingIOError:
                            pass
                    selector.modify(connection, selectors.EVENT_READ | (
                        selectors.EVENT_WRITE if peer.output and sending else 0), ('peer', lane))
        except Exception as exception:
            error = str(exception)
        finally:
            if process.poll() is None:
                process.kill()
            returncode = process.wait()
            selector.close()
            for server in servers:
                server.close()
            for peer in peers:
                if peer.connection:
                    peer.connection.close()
            for debugger, _ in debuggers.values():
                if debugger.poll() is None:
                    debugger.kill()
                    debugger.wait()
            if fault_debugger is not None and fault_debugger.poll() is None:
                fault_debugger.kill()
                fault_debugger.wait()
            for debugger, _, reply_armed, reply_released in reply_debuggers.values():
                if debugger.poll() is None:
                    debugger.kill()
                    debugger.wait()
                reply_armed.unlink(missing_ok=True)
                reply_released.unlink(missing_ok=True)
            armed.unlink(missing_ok=True)
            control.unlink(missing_ok=True)
    text = log.read_text(errors='replace')
    required = ['IPV4_LOOPBACK_PASS', 'IPV4_CONFIG_PASS', 'IPV4_LOCAL_ADDRESS_PASS',
                'IPV4_HOST_MASK_LOCAL_PASS',
                'IPV4_WIRE_VIRTIO_PASS', 'IPV4_WIRE_E1000_PASS', 'IPV4_ROUTING_PASS', 'IPV4_SOCKET_PASS',
                'IPV4_RAW_CONTRACT_PASS', 'IPV4_RAW_CHECKSUM_PASS',
                'IPV4_RX_QUEUE_PASS',
                'IPV4_PRESSURE_PASS index=1', 'IPV4_PRESSURE_PASS index=2',
                'IPV4_ARP_FAILURE_PASS index=1', 'IPV4_ARP_FAILURE_PASS index=2',
                'IPV4_ICMP_ERROR_PASS index=1', 'IPV4_ICMP_ERROR_PASS index=2',
                'IPV4_INPUT_PASS index=1', 'IPV4_INPUT_PASS index=2',
                'IPV4_CACHE_EXPIRY_PASS index=1', 'IPV4_CACHE_EXPIRY_PASS index=2',
                'IPV4_LIMITS_PASS index=1', 'IPV4_LIMITS_PASS index=2',
                'IPV4_RECEIVE_LIFETIME_PASS index=1', 'IPV4_RECEIVE_LIFETIME_PASS index=2',
                'IPV4_LINK_PASS index=1', 'IPV4_LINK_PASS index=2',
                'IPV4_CACHE_REPLACEMENT_PASS index=1', 'IPV4_CACHE_REPLACEMENT_PASS index=2',
                'IPV4_ARP_REPLY_PASS index=1', 'IPV4_ARP_REPLY_PASS index=2',
                'IPV4_BUSYBOX_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    missing = [marker for marker in required if marker not in text]
    if fault:
        required = ['IPV4_LOOPBACK_PASS', 'IPV4_RAW_CONTRACT_PASS', 'IPV4_RAW_CHECKSUM_PASS',
                    'IPV4_CONFIG_PASS', 'IPV4_DEVICE_FAULT_PASS', 'IPV4_OTHER_NIC_PASS',
                    'IPV4_SOCKET_PASS', 'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
        missing = [marker for marker in required if marker not in text]
        debug_text = fault_log.read_text(errors='replace') if fault_log else ''
        passed = 'PACKET_FAULT_INJECTED model=virtio kind=id' in debug_text and \
                 peers[0].arp == 1 and peers[0].echo == 0 and peers[1].arp == 1 and peers[1].echo == 1
    else:
        reply_injected = len(reply_debuggers) == 2 and all(
            debugger.returncode == 0 and f'IPV4_ARP_REPLY_HELD index={lane + 1}' in debug_log.read_text() and
            f'IPV4_ARP_REPLY_RESUMED index={lane + 1}' in debug_log.read_text()
            for lane, (debugger, debug_log, _, _) in reply_debuggers.items())
        passed = reply_injected and len(link_events) == 4 and all(peer.arp >= 2 and peer.echo == len(peer.targets) and
                     peer.bad_arp == 11 and peer.bad_ip == 15 and
                     peer.pressure == 33 and peer.pressure_arp >= 1 and
                     len(peer.missing_arp) == 3 and peer.error_tests == 1 and
                     peer.host_echo == 1 and peer.protocol_error == 1 and
                     peer.cache_ack and peer.cache_arp == 1 and peer.broadcast == 1 and
                     peer.lifetime == 1 and peer.alias_echo == 132 and peer.alias_reply == 1 and
                     sum(peer.alias_arp.values()) == 130 and peer.held_replies == 1 and
                     peer.reply_ingress == 97 for peer in peers)
    result = dict(firmware=firmware, transport=transport, fault=fault, returncode=returncode, timed_out=timed_out,
                  error=error, missing=missing, arp=[peer.arp for peer in peers],
                  echo=[peer.echo for peer in peers], foreign=[peer.foreign for peer in peers],
                  malformed_arp=[peer.bad_arp for peer in peers],
                  malformed_ipv4=[peer.bad_ip for peer in peers],
                  pressure=[peer.pressure for peer in peers], pressure_arp=[peer.pressure_arp for peer in peers],
                  unanswered_arp=[len(peer.missing_arp) for peer in peers],
                  icmp_error_tests=[peer.error_tests for peer in peers],
                  kernel_echo=[peer.host_echo for peer in peers], protocol_errors=[peer.protocol_error for peer in peers],
                  cache_expired=[peer.cache_ack for peer in peers], cache_arp=[peer.cache_arp for peer in peers],
                  broadcasts=[peer.broadcast for peer in peers],
                  receive_lifetime=[peer.lifetime for peer in peers],
                  link_events=len(link_events),
                  cache_replacement_arp=[sum(peer.alias_arp.values()) for peer in peers],
                  cache_replacement_echo=[peer.alias_echo for peer in peers],
                  cache_refresh_reply=[peer.alias_reply for peer in peers],
                  held_arp_replies=[peer.held_replies for peer in peers],
                  arp_reply_ingress=[min(peer.reply_ingress, 96) for peer in peers],
                  seconds=round(time.monotonic() - started, 2), log=log.name,
                  passed=returncode == 1 and not timed_out and not error and not missing and passed)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print('\n'.join(text.splitlines()[-25:]), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy'], default='modern')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--fault', action='store_true', help='quarantine one real virtio RX queue through GDB')
    args = parser.parse_args()
    fixture(program='ipv4-tests', script='userspace/tests/net/ipv4.sh',
            environment={'AXIOM64_IP_FAULT': '1'} if args.fault else None)
    subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'ipv4-test.iso'], cwd=ROOT, check=True)
    results = [run(firmware, args.transport, args.timeout, args.fault) for firmware in
               (['bios', 'uefi'] if args.firmware == 'both' else [args.firmware])]
    (ROOT / 'build/ipv4-results.json').write_text(json.dumps(results, indent=2) + '\n')
    raise SystemExit(0 if all(result['passed'] for result in results) else 1)

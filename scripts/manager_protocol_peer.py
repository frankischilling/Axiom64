# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent DHCP packets for actual concurrent manager acceptance tests."""
import struct
import time
from dhcp_peer import Peer, check, checksum

SCENARIOS = ('reply-rejection', 'loss-reorder', 'options', 'manual-resolver', 'nak-request', 'nak-reboot',
             'nak-renew', 'nak-rebind', 'renew-ack', 'expiry', 'infinite',
             'infinite-timers', 'default-timers', 'invalid-timers',
             'conflict-probe', 'conflict-claim', 'dhcp-defense')
BAD_REPLIES = ('transaction', 'hardware-address', 'client-identifier', 'bootp-op',
               'hardware-length', 'cookie', 'missing-server', 'broadcast-server',
               'missing-type', 'type-length', 'mask-length', 'mask', 'lease-length',
               'lease-zero', 'missing-lease', 'renewal-length', 'rebinding-length',
               'dns-length', 'dns-multicast', 'domain', 'search-pointer',
               'route-prefix', 'route-length', 'overload', 'overload-end',
               'duplicate-type', 'duplicate-lease', 'tlv-length', 'missing-end',
               'ip-checksum', 'udp-checksum', 'ip-length', 'fragment', 'ttl',
               'udp-length', 'source-port', 'destination-port', 'address', 'destination')


def fingerprint(frame):
    value = 14695981039346656037
    for byte in frame:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return f'{value:016x}'


def tlvs(rows):
    return b''.join(bytes([code, len(value)]) + value for code, value in rows) + b'\xff'


def client_packet(frame, guest):
    """Check outbound bytes without calling the production codec or state machine."""
    check(42 <= len(frame) <= 1518 and frame[6:12] == guest, 'real client Ethernet source')
    check(frame[12:14] == b'\x08\x00', 'client IPv4 EtherType')
    ip = frame[14:34]
    total = int.from_bytes(ip[2:4], 'big')
    check(ip[0] == 0x45 and 268 <= total <= len(frame) - 14 and ip[9] == 17 and
          ip[8] and int.from_bytes(ip[6:8], 'big') & ~0x4000 == 0 and checksum(ip) == 0,
          'client IPv4 version, lengths, fragmentation and checksum')
    udp = frame[34:14 + total]
    check(udp[:4] == struct.pack('!HH', 68, 67) and len(udp) >= 248 and
          int.from_bytes(udp[4:6], 'big') == len(udp) and udp[6:8] != b'\0\0',
          'client UDP ports, exact length and computed checksum')
    check(checksum(ip[12:20] + b'\0\x11' + struct.pack('!H', len(udp)) + udp) == 0,
          'client UDP pseudo-header checksum')
    message = udp[8:]
    check(message[:3] == b'\x01\x01\x06' and message[28:34] == guest and
          message[236:240] == bytes.fromhex('63825363'), 'client BOOTP identity and cookie')
    at, rows, ended = 240, {}, False
    while at < len(message):
        code = message[at]
        at += 1
        if code == 255:
            ended = True
            break
        if not code:
            continue
        check(at < len(message), 'client TLV length header')
        size = message[at]
        at += 1
        check(at + size <= len(message) and code not in rows, 'client TLV bounds and uniqueness')
        rows[code] = message[at:at + size]
        at += size
    check(ended and rows.get(61) == b'\x01' + guest and len(rows.get(53, b'')) == 1,
          'client END, type and stable identifier')
    if rows[53] not in (b'\x04', b'\x07'):
        requested = rows.get(55, b'')
        check(set(requested) == {1, 3, 6, 15, 51, 58, 59, 119, 121} and
              len(requested) == 9 and requested.index(121) < requested.index(3),
              'RFC 3442 parameter request list: classless routes precede Router')
    else:
        check(55 not in rows and 12 not in rows, 'DECLINE/RELEASE omit request list and hostname')
    return ip, message, rows


class ProtocolPeer(Peer):
    def __init__(self, lane, scenario, affected):
        super().__init__(lane)
        check(scenario in SCENARIOS and affected in (0, 1), 'known protocol fixture selection')
        self.scenario = scenario if lane == affected else 'healthy'
        self.affected = lane == affected
        self.lease_timers = (600, 300, 525)
        if self.scenario in ('nak-renew', 'nak-rebind', 'renew-ack', 'expiry',
                             'default-timers', 'invalid-timers', 'infinite-timers'):
            self.lease_timers = (36, 12, 24)
        if self.scenario in ('infinite', 'infinite-timers'):
            self.lease_timers = (0xffffffff, 12, 24)
        if self.scenario == 'invalid-timers':
            self.lease_timers = (36, 35, 2)
        self.rebound_timers = (600, 300, 525)
        self.sequence = self.reboots = self.declines = self.conflicts = 0
        self.sent, self.received = [], []
        self.unmatched = []
        self.gate = None
        self.bad_queue = []
        self.waiting_delivery = None
        self.revoked = self.reacquiring = self.changed = False
        self.first_transaction = self.old_transaction = None
        self.renewal_transaction = None
        self.acks = self.defenses = 0
        self.reply_flags, self.client_address = b'\x80\0', bytes(4)

    def send(self, frame, label='arp-reply'):
        record = dict(sequence=len(self.sent) + 1, label=label, frame=frame.hex(),
                      hash=fingerprint(frame), length=len(frame), delivered=False)
        self.sent.append(record)
        super().send(frame)
        return record

    def receipt(self, length, digest, milliseconds, packet_type):
        rows = self.received if packet_type == 4 else self.sent
        for record in rows:
            if 'guest_ms' not in record and record['hash'] == digest and record['length'] == length:
                record.update(delivered=True, guest_ms=milliseconds)
                return
        self.unmatched.append(dict(length=length, hash=digest, guest_ms=milliseconds,
                                   packet_type=packet_type))

    def reply(self, kind, transaction, changed=False, variant=None, server=None, unicast=False,
              ciaddr=None):
        self.sequence += 1
        source = server or (self.other if changed else self.ip)
        fresh = changed or self.scenario == 'options' and kind == 5 or variant is not None
        mask = bytes.fromhex('ffffff80' if fresh else 'ffffff00')
        dns = bytes([10, 23, self.lane + 1, 99 if kind == 2 or variant else 54 if fresh else 53])
        timers = self.rebound_timers if changed else self.lease_timers
        rows = [(53, bytes([kind])), (54, source), (61, b'\x01' + self.guest),
                (1, mask), (3, self.other if fresh else self.ip), (6, dns),
                (15, b'lab.example'), (51, struct.pack('!I', timers[0]))]
        if not (self.scenario in ('infinite', 'default-timers') or changed and
                self.scenario == 'infinite-timers'):
            rows += [(58, struct.pack('!I', timers[1])), (59, struct.pack('!I', timers[2]))]
        if changed and self.scenario == 'infinite-timers':
            rows = [(code, struct.pack('!I', 0xffffffff) if code == 51 else value)
                    for code, value in rows]
        if kind == 6:
            rows = [(code, value) for code, value in rows if code in (53, 54, 61)]
        message = bytearray(240)
        message[:3] = b'\x02\x01\x06'
        message[4:8], message[10:12], message[28:34] = transaction, self.reply_flags, self.guest
        if kind == 5:
            message[12:16] = self.client_address if ciaddr is None else ciaddr
        if kind in (2, 5):
            message[16:20] = self.address
        message[236:240] = bytes.fromhex('63825363')
        replacements = {'client-identifier': (61, b'\x01' + self.guest[:-1] + b'\x77'),
                        'broadcast-server': (54, b'\xff' * 4), 'type-length': (53, bytes([kind, kind])),
                        'mask-length': (1, mask[:3]), 'mask': (1, bytes.fromhex('ff00ff00')),
                        'lease-length': (51, b'\x01\x02\x03'), 'lease-zero': (51, bytes(4)),
                        'renewal-length': (58, bytes(3)), 'rebinding-length': (59, bytes(3)),
                        'dns-length': (6, dns[:3]), 'dns-multicast': (6, b'\xe0\0\0\x01'),
                        'domain': (15, b'bad\nname'), 'search-pointer': (119, b'\xc0\0'),
                        'route-prefix': (121, b'\x21' + bytes(8)), 'route-length': (121, b'\x18\xac'),
                        'overload': (52, b'\0'), 'overload-end': (52, b'\x01')}
        if variant in replacements:
            code, value = replacements[variant]
            rows = [(c, v) for c, v in rows if c != code] + [(code, value)]
        if variant in ('missing-server', 'missing-type', 'missing-lease'):
            omitted = {'missing-server': 54, 'missing-type': 53, 'missing-lease': 51}[variant]
            rows = [(c, v) for c, v in rows if c != omitted]
        if variant in ('duplicate-type', 'duplicate-lease'):
            code = 53 if variant == 'duplicate-type' else 51
            rows.append(next(row for row in rows if row[0] == code))
        if variant == 'transaction':
            message[4] ^= 1
        elif variant == 'hardware-address':
            message[33] ^= 1
        elif variant == 'bootp-op':
            message[0] = 1
        elif variant == 'hardware-length':
            message[2] = 5
        elif variant == 'cookie':
            message[239] ^= 1
        elif variant == 'address':
            message[16:20] = self.address[:-1] + b'\x29' if kind == 5 else bytes(4)
        if self.scenario == 'options' and kind == 5 and not variant:
            search = b'\x03lab\x07example\0\x03dev\xc0\x04'
            routes = b'\0' + self.other + b'\x10\xac\x10' + bytes(4)
            dns += b'\x01\x01\x01\x01'
            rows = [(c, self.ip if c == 3 else v) for c, v in rows if c not in (1, 6)]
            rows += [(52, b'\x03'), (1, mask[:2]), (6, dns[:3]),
                     (119, search[:6]), (121, routes[:2])]
            file = tlvs([(1, mask[2:]), (6, dns[3:5]), (119, search[6:12]), (121, routes[2:7])])
            sname = tlvs([(6, dns[5:]), (119, search[12:]), (121, routes[7:])])
            check(len(file) <= 128 and len(sname) <= 64, 'overloaded reply field bounds')
            message[108:108 + len(file)], message[44:44 + len(sname)] = file, sname
        options = tlvs(rows)
        if variant == 'missing-end':
            options = options[:-1]
        elif variant == 'tlv-length':
            options = options[:-1] + b'\x06\x08\x01\xff'
        message += options
        destination = self.address if unicast else b'\xff' * 4
        if variant == 'destination':
            destination = self.address[:-1] + b'\x77'
        udp = bytearray(struct.pack('!HHHH', 67, 68, len(message) + 8, 0) + message)
        if variant == 'source-port':
            struct.pack_into('!H', udp, 0, 69)
        if variant == 'destination-port':
            struct.pack_into('!H', udp, 2, 69)
        pseudo = source + destination + b'\0\x11' + struct.pack('!H', len(udp))
        struct.pack_into('!H', udp, 6, checksum(pseudo + udp) or 65535)
        if variant == 'udp-checksum':
            udp[7] ^= 1
        if variant == 'udp-length':
            struct.pack_into('!H', udp, 4, len(udp) + 1)
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, len(udp) + 20,
                                  self.sequence & 65535, 0x4000, 64, 17, 0, source, destination))
        if variant == 'fragment':
            struct.pack_into('!H', ip, 6, 0x2000)
        if variant == 'ttl':
            ip[8] = 0
        if variant == 'ip-length':
            struct.pack_into('!H', ip, 2, len(udp) + 21)
        struct.pack_into('!H', ip, 10, checksum(ip))
        if variant == 'ip-checksum':
            ip[11] ^= 1
        return (self.guest if unicast else b'\xff' * 6) + self.mac + b'\x08\x00' + ip + udp

    def answer(self, kind, transaction, changed=False, **kwargs):
        frame = self.reply(kind, transaction, changed, **kwargs)
        self.send(frame, f'{kind}-' + (kwargs.get('variant') or ('changed' if changed else 'valid')))
        if kind == 5 and not kwargs.get('variant'):
            self.ack_server = kwargs.get('server') or (self.other if changed else self.ip)
            self.changed = changed
            self.acks += 1
            self.ann_before_ack = self.announcements

    def packet(self, frame):
        record = dict(sequence=len(self.received) + 1, frame=frame.hex(), hash=fingerprint(frame),
                      length=len(frame), host_monotonic=time.monotonic())
        self.received.append(record)
        for observation in self.unmatched:
            if observation['packet_type'] == 4 and observation['hash'] == record['hash'] and \
                    observation['length'] == record['length']:
                record.update(delivered=True, guest_ms=observation['guest_ms'])
                self.unmatched.remove(observation)
                break
        if frame[12:14] == b'\x08\x06':
            before = self.probes, self.announcements
            super().arp(frame)
            if self.scenario == 'conflict-probe' and self.probes > before[0] and not self.conflicts:
                self.conflict()
            elif self.scenario == 'conflict-claim' and self.announcements == 1:
                self.gate = 'claim-conflict'
            elif self.scenario in ('conflict-claim', 'dhcp-defense') and self.conflicts and not self.revoked and \
                    self.announcements > before[1]:
                self.defenses += 1
                self.conflict()
            return
        ip, message, options = client_packet(frame, self.guest)
        kind, transaction = options[53][0], message[4:8]
        self.reply_flags, self.client_address = message[10:12], message[12:16]
        record.update(kind=kind, transaction=transaction.hex())
        check(transaction != bytes(4), 'nonzero real transaction identifier')
        configured = message[12:16] == self.address
        if kind == 1:
            self.discovers += 1
            check(ip[12:20] == bytes(4) + b'\xff' * 4 and frame[:6] == b'\xff' * 6 and
                  message[10:12] == b'\x80\0' and message[12:16] == bytes(4) and
                  50 not in options and 54 not in options, 'independent unconfigured DISCOVER')
            if self.acks and self.scenario == 'expiry' and not self.revoked:
                self.revoked = True
                self.old_transaction = self.renewal_transaction
            if self.revoked:
                check(transaction != self.old_transaction, 'fresh transaction after revocation')
                if not self.reacquiring:
                    self.transaction = transaction
                    self.reacquiring = True
                    self.gate = 'withdrawn'
                    if self.scenario == 'expiry':
                        self.send(self.reply(5, self.old_transaction, changed=True, ciaddr=self.address),
                                  'expired-lease-ACK')
                    return
            if self.transaction is None:
                self.transaction = self.first_transaction = transaction
            check(transaction == self.transaction, 'retries retain their current transaction')
            if self.gate:
                return
            if self.scenario == 'reply-rejection' and not self.reacquiring:
                self.reject_queue(2)
            elif self.scenario == 'loss-reorder' and not self.reacquiring:
                if self.discovers == 1:
                    return
                self.gate = 'reject-offer'
                self.bad_queue = [(self.reply(5, transaction), 'ACK-before-OFFER'),
                                  (self.reply(2, transaction, variant='transaction'), 'unrelated-OFFER')]
            else:
                if self.affected and not self.reacquiring and self.discovers == 1:
                    self.gate = 'initial-offer'
                else:
                    self.answer(2, transaction, changed=self.reacquiring and
                                self.scenario not in ('nak-request', 'nak-reboot'))
        elif kind == 3 and not configured:
            check(ip[12:20] == bytes(4) + b'\xff' * 4 and frame[:6] == b'\xff' * 6 and
                  message[12:16] == bytes(4) and message[10:12] == b'\x80\0' and
                  options.get(50) == self.address, 'independent initial DHCPREQUEST')
            if 54 not in options:
                check(self.scenario == 'nak-reboot' and not self.revoked,
                      'only prepared saved hint enters INIT-REBOOT')
                self.reboots += 1
                self.old_transaction = transaction
                self.revoked = True
                self.answer(6, transaction)
                return
            changed = self.reacquiring and self.scenario not in ('nak-request', 'nak-reboot')
            check(transaction == self.transaction and options[54] == (self.other if changed else self.ip),
                  'REQUEST retains the selected server, address and transaction')
            self.selecting += 1
            if self.scenario == 'nak-request' and not self.revoked:
                self.old_transaction = transaction
                self.revoked = True
                self.answer(6, transaction)
            elif self.scenario == 'reply-rejection' and not self.reacquiring and not self.gate:
                self.reject_queue(5)
            elif self.scenario == 'loss-reorder' and not self.reacquiring:
                if self.selecting == 1:
                    return  # Exercise retransmission after a lost selected-request reply.
                if not self.gate:
                    self.gate = 'reject-ack'
                    self.bad_queue = [(self.reply(2, transaction, server=self.other), 'late-competing-OFFER'),
                                      (self.reply(5, transaction, variant='transaction'), 'unrelated-ACK'),
                                      (self.reply(5, transaction, changed=True), 'unselected-server-ACK')]
            elif not self.affected:
                self.answer(5, transaction)
            elif not self.gate:
                self.gate = 'initial-ack'
        elif kind == 3 and configured:
            check(ip[12:16] == self.address and 50 not in options and 54 not in options,
                  'configured request omits requested-address and server options')
            if self.renewal_transaction is None:
                check(transaction != self.transaction, 'renewal starts a fresh exchange')
                self.renewal_transaction = transaction
            check(transaction == self.renewal_transaction, 'T1/T2 share the renewal transaction')
            if ip[16:20] == self.ack_server:
                self.renewals += 1
                check(message[10:12] == bytes(2) and frame[:6] == self.mac,
                      'real T1 uses unicast destination, routed MAC and cleared broadcast flag')
                if self.scenario == 'renew-ack' and self.acks == 1:
                    self.answer(5, transaction, changed=True, server=self.ip, unicast=True)
                elif self.scenario == 'nak-renew' and not self.revoked and not self.gate:
                    self.gate = 'renew-nak'
                    self.bad_queue = [(self.reply(6, transaction, unicast=True), 'unicast-renew-NAK'),
                                      (self.reply(6, transaction, server=self.other), 'unselected-renew-NAK')]
                else:
                    check(self.scenario in ('nak-rebind', 'expiry', 'infinite-timers',
                                           'default-timers', 'invalid-timers'),
                          'unexpected renewal in a lease with distant or absent T1')
            else:
                self.rebindings += 1
                check(ip[16:20] == b'\xff' * 4 and frame[:6] == b'\xff' * 6 and
                      message[10:12] == b'\x80\0' and self.renewals,
                      'real T2 broadcasts after the unanswered T1 exchange')
                if self.scenario == 'nak-rebind' and not self.revoked and not self.gate:
                    self.gate = 'rebind-nak'
                    self.bad_queue = [(self.reply(6, transaction, server=self.other, unicast=True),
                                       'unicast-rebind-NAK')]
                elif self.scenario in ('infinite-timers', 'default-timers', 'invalid-timers'):
                    self.answer(5, transaction, changed=True)
                else:
                    check(self.scenario == 'expiry', 'only expiry ignores a valid T2 request')
        elif kind == 4:
            self.declines += 1
            check(self.conflicts and self.declines == 1 and not configured and
                  message[12:16] == bytes(4) and message[10:12] == bytes(2) and
                  ip[12:20] == bytes(4) + b'\xff' * 4 and
                  options.get(50) == self.address and options.get(54) == self.ack_server,
                  'actual DHCPDECLINE identifies the conflicting accepted candidate')
            self.old_transaction = transaction
            self.revoked = True
            self.gate = None
        elif kind == 7:
            self.releases += 1
            check(configured and ip[12:16] == self.address and ip[16:20] == self.ack_server and
                  frame[:6] == self.mac and message[10:12] == bytes(2) and
                  options.get(54) == self.ack_server and 50 not in options,
                  'RELEASE goes only to the last accepted ACK server with its owned address')
        else:
            raise RuntimeError('unexpected real client DHCP mode')

    def reject_queue(self, kind):
        self.gate = 'reject-offer' if kind == 2 else 'reject-ack'
        self.bad_queue = [(self.reply(kind, self.transaction, variant=variant,
                                     server=self.other if kind == 2 else None),
                           f'rejected-{kind}-{variant}') for variant in BAD_REPLIES]
        if kind == 5:
            self.bad_queue.append((self.reply(5, self.transaction, changed=True), 'unselected-server-ACK'))

    def tick(self, healthy):
        if not healthy:
            return
        if self.waiting_delivery and not self.waiting_delivery['delivered']:
            return
        if self.bad_queue:
            frame, label = self.bad_queue.pop(0)
            self.waiting_delivery = self.send(frame, label)

    def rejected_delivered(self):
        return not self.bad_queue and self.waiting_delivery is not None and self.waiting_delivery['delivered']

    def approve(self):
        gate = self.gate
        self.gate = None
        self.waiting_delivery = None
        if gate in ('initial-offer', 'reject-offer'):
            self.answer(2, self.transaction)
            if self.scenario == 'loss-reorder':
                self.answer(2, self.transaction)  # Duplicate the same offer independently.
        elif gate in ('initial-ack', 'reject-ack'):
            changed = self.reacquiring and self.scenario not in ('nak-request', 'nak-reboot')
            self.answer(5, self.transaction, changed=changed)
            if self.scenario == 'loss-reorder':
                self.send(self.reply(5, self.transaction), 'duplicate-accepted-ACK')
                self.send(self.reply(2, self.transaction, server=self.other), 'OFFER-after-ACK')
        elif gate in ('renew-nak', 'rebind-nak'):
            self.old_transaction = self.renewal_transaction
            self.revoked = True
            self.answer(6, self.renewal_transaction, server=self.other if gate == 'rebind-nak' else self.ip)
        elif gate == 'withdrawn':
            self.answer(2, self.transaction, changed=self.scenario not in ('nak-request', 'nak-reboot'))
        elif gate in ('claim-conflict', 'defense-conflict'):
            self.conflict()
        else:
            raise RuntimeError(f'unknown peer approval gate {gate}')

    def conflict(self):
        self.conflicts += 1
        arp = bytes.fromhex('0001080006040001') + self.mac + self.address + bytes(6) + self.address
        self.send((b'\xff' * 6 + self.mac + b'\x08\x06' + arp).ljust(60, b'\0'),
                  f'address-conflict-{self.conflicts}')

    def counts(self):
        names = ('discovers', 'selecting', 'renewals', 'rebindings', 'releases', 'probes',
                 'announcements', 'resolutions', 'reboots', 'declines', 'conflicts', 'defenses', 'acks')
        return {name: getattr(self, name) for name in names}

    def verify(self):
        check(self.releases == 1 and self.probes >= 3 and self.announcements >= 2,
              'each adapter acquires, probes, announces and releases its final accepted lease')
        check(all(record['delivered'] for record in self.sent),
              'every injected packet has an actual guest driver receive receipt')
        check(all('guest_ms' in record for record in self.received),
              'every observed client packet has an independent actual guest clock receipt')
        check(not self.unmatched, 'capture has no unmatched driver observations')
        configured = [record for record in self.received if record.get('kind') == 3 and
                      bytes.fromhex(record['frame'])[54:58] == self.address]
        if configured:
            initial = next(record for record in self.received if record.get('kind') == 3 and
                           bytes.fromhex(record['frame'])[54:58] == bytes(4))['guest_ms']
            default = self.scenario in ('default-timers', 'invalid-timers')
            for record in configured:
                unicast = bytes.fromhex(record['frame'])[30:34] == self.ip
                lower, upper = ((17100, 18900) if unicast else (31050, 31950)) if default else (
                    (12000, 12000) if unicast else (24000, 24000))
                elapsed = record['guest_ms'] - initial
                check(lower - 500 <= elapsed <= upper + 500,
                      f'actual guest T{1 if unicast else 2} window: {elapsed} ms expected {lower}..{upper}')
        if not self.affected:
            check(self.acks == 1 and self.selecting == 1 and self.probes == 3 and
                  self.announcements == 2 and not self.renewals and not self.rebindings and
                  not self.declines and not self.conflicts, 'healthy adapter progresses independently')
        elif self.scenario == 'loss-reorder':
            check(self.discovers >= 2 and self.selecting >= 2 and self.probes == 3,
                  'lost requests retry without accepting reordered/duplicate replies twice')
        elif self.scenario in ('nak-renew', 'renew-ack'):
            check(self.renewals == 1 and not self.rebindings and self.acks == 2,
                  'T1 renewal/revocation completes and final state is accepted')
        elif self.scenario in ('nak-rebind', 'expiry', 'infinite-timers', 'default-timers', 'invalid-timers'):
            check(self.renewals == self.rebindings == 1 and self.acks == 2,
                  'real T1/T2 and fresh accepted lease after rebinding/expiry')
        elif self.scenario == 'infinite':
            check(not self.renewals and not self.rebindings and self.acks == 1,
                  'infinite lease without finite timers never renews during the observed interval')
        elif self.scenario.startswith('conflict-') or self.scenario == 'dhcp-defense':
            check(self.declines == 1 and self.acks == 2 and
                  self.conflicts == (1 if self.scenario == 'conflict-probe' else 2),
                  'real conflict produces DECLINE, bounded backoff and fresh reacquisition')
        if self.scenario == 'nak-reboot':
            check(self.reboots == 1 and self.acks == 1, 'saved-address NAK triggers fresh discovery')
        return self.counts()

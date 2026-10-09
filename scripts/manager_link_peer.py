# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent packet peers for actual carrier and adapter-failure tests."""
from dhcp_peer import Peer, check
from manager_protocol_peer import ProtocolPeer, client_packet, fingerprint
import time

SCENARIOS = ('carrier-initial', 'carrier-selecting', 'carrier-probing', 'carrier-bound',
             'carrier-flap', 'carrier-infinite', 'static-initial', 'static-probing',
             'static-bound', 'disabled', 'disabled-initial', 'disabled-failed', 'failed-selecting', 'failed-probing',
             'failed-bound', 'failed-infinite', 'static-failed', 'rx-length',
             'manual-carrier', 'manual-failed')


class LinkPeer(ProtocolPeer):
    def __init__(self, lane, scenario, affected):
        # The existing independent codec/capture implementation is shared;
        # this peer owns its separate exchange and carrier policy below.
        super().__init__(lane, 'manual-resolver', affected)
        self.link_scenario = scenario
        self.fixed = lane == affected and scenario.startswith('static-')
        self.disabled = lane == affected and scenario.startswith('disabled')
        self.failed = lane == affected and (scenario.startswith('failed-') or
                                           scenario in ('static-failed', 'manual-failed', 'disabled-failed'))
        self.infinite = lane == affected and scenario.endswith('infinite')
        self.scenario = 'infinite' if self.infinite else 'manual-resolver'
        self.lease_timers = (0xffffffff, 0, 0) if self.infinite else (
            (600, 300, 525) if lane == affected else (120, 20, 105))
        self.rebound_timers = (0xffffffff, 0, 0) if self.infinite else (600, 300, 525)
        self.exchange = None
        self.pending_offer = self.pending_ack = self.pending_renewal = None
        self.offer_allowed = self.ack_allowed = False
        self.restored = False
        self.accepted_before = False
        self.approved = set()
        self.old_transactions = set()
        self.saved_revalidation = False
        self.disconnected = False
        self.drop = None

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
        check(not self.disabled, 'saved-disabled adapter never emits manager traffic')
        if frame[12:14] == b'\x08\x06':
            Peer.arp(self, frame)
            return
        check(not self.fixed, 'saved static override never emits DHCP')
        ip, message, options = client_packet(frame, self.guest)
        kind, transaction = options[53][0], message[4:8]
        record.update(kind=kind, transaction=transaction.hex())
        check(transaction != bytes(4), 'real nonzero transaction')
        self.reply_flags, self.client_address = message[10:12], message[12:16]
        configured = message[12:16] == self.address
        if kind == 1:
            self.discovers += 1
            check(ip[12:20] == bytes(4) + b'\xff' * 4 and frame[:6] == b'\xff' * 6 and
                  message[10:12] == b'\x80\0' and message[12:16] == bytes(4) and
                  50 not in options and 54 not in options, 'actual unconfigured DISCOVER')
            if self.restored:
                check(transaction not in self.old_transactions, 'carrier return uses a fresh transaction')
            self.exchange = transaction
            self.pending_offer = record
        elif kind == 3 and not configured:
            check(ip[12:20] == bytes(4) + b'\xff' * 4 and frame[:6] == b'\xff' * 6 and
                  message[10:12] == b'\x80\0' and options.get(50) == self.address,
                  'actual selected or saved-address request')
            if 54 not in options:
                check(self.affected and self.restored and self.accepted_before,
                      'INIT-REBOOT requires the retained accepted lease')
                check(transaction not in self.old_transactions, 'fresh saved-address revalidation')
                self.reboots += 1
                self.saved_revalidation = True
                self.exchange = transaction
            else:
                check(transaction == self.exchange and options[54] == (
                    self.other if self.restored and self.accepted_before else self.ip),
                    'selected server and transaction match the actual offer')
                self.selecting += 1
            self.pending_ack = record
        elif kind == 3 and configured:
            check(not self.affected and ip[12:16] == self.address and ip[16:20] == self.ip and
                  frame[:6] == self.mac and message[10:12] == bytes(2) and
                  50 not in options and 54 not in options,
                  'healthy adapter completes an actual unicast T1 exchange')
            self.renewals += 1
            self.pending_renewal = record
        elif kind == 7:
            self.releases += 1
            check(configured and self.acks and ip[12:16] == self.address and
                  ip[16:20] == self.ack_server and frame[:6] == self.mac and
                  message[10:12] == bytes(2) and options.get(54) == self.ack_server and
                  50 not in options,
                  'RELEASE names only the final accepted lease and server')
        else:
            raise RuntimeError('unexpected real client mode during carrier/failure test')

    def respond(self, kind, record):
        frame = bytes.fromhex(record['frame'])
        transaction = bytes.fromhex(record['transaction'])
        self.reply_flags, self.client_address = frame[52:54], frame[54:58]
        key = transaction, self.client_address
        if kind == 5 and key in self.approved:
            return
        self.answer(kind, transaction, changed=self.restored and self.accepted_before)
        if kind == 5:
            self.approved.add(key)

    def tick(self, healthy_ready, down_ms):
        if self.fixed or self.disabled or self.disconnected:
            return
        if not self.affected:
            if self.pending_offer:
                self.respond(2, self.pending_offer)
                self.pending_offer = None
            if self.pending_ack:
                self.respond(5, self.pending_ack)
                self.pending_ack = None
            renewal = self.pending_renewal
            if renewal and down_ms is not None and renewal.get('guest_ms', -1) >= down_ms:
                self.lease_timers = (600, 300, 525)
                self.respond(5, renewal)
                self.pending_renewal = None
            return
        if healthy_ready and self.pending_offer and self.offer_allowed:
            self.respond(2, self.pending_offer)
            self.pending_offer = None
        if self.pending_ack and self.ack_allowed:
            self.respond(5, self.pending_ack)
            self.pending_ack = None

    def interrupt(self):
        self.old_transactions |= {bytes.fromhex(record['transaction']) for record in self.received
                                  if record.get('kind') in (1, 3)}
        self.pending_offer = self.pending_ack = None
        self.offer_allowed = self.ack_allowed = False

    def resume(self, accepted):
        self.restored = True
        self.accepted_before = accepted
        self.offer_allowed = True
        self.ack_allowed = True
        self.exchange = None

    def verify(self, down_ms, permanent):
        check(not self.unmatched, 'every independent raw receipt matches a host packet')
        for record in self.sent:
            check(record['delivered'] or record.get('drop') == 'rx-length',
                  'server frames are delivered except the proved corrupt completion')
        check(all('guest_ms' in record for record in self.received),
              'every transmitted client frame has an actual guest clock receipt')
        if not self.affected:
            check(self.acks == 2 and self.renewals >= 1 and not self.rebindings and
                  self.probes == 3 and self.announcements == 2 and self.releases == 1,
                  'healthy adapter acquires, renews and releases independently')
            renewals = [record for record in self.received if record.get('kind') == 3 and
                        bytes.fromhex(record['frame'])[54:58] == self.address]
            initial = next(record for record in self.received if record.get('kind') == 3 and
                           bytes.fromhex(record['frame'])[54:58] == bytes(4))
            check(19500 <= renewals[0]['guest_ms'] - initial['guest_ms'] <= 20500,
                  'healthy actual first T1 occurs at twenty seconds')
            check(any(record['guest_ms'] >= down_ms for record in renewals),
                  'healthy renewal packet occurs while the affected adapter is down/failed')
        elif self.disabled:
            check(not self.sent and not self.received and not self.acks and not self.releases,
                  'saved-disabled adapter stays silent and unowned')
        elif self.fixed:
            check(not any(record.get('kind') for record in self.received) and not self.acks and
                  not self.releases and self.probes >= 3,
                  'static override probes and never falls back to DHCP')
        else:
            expected_release = 0 if permanent or self.link_scenario.startswith('manual-') else 1
            check(self.releases == expected_release, 'only a usable accepted final lease is released')
            if not permanent and not self.link_scenario.startswith('manual-'):
                check(self.acks >= 1 and self.probes >= 3 and self.announcements >= 2,
                      'returned healthy driver completes valid acquisition')
            if self.restored and self.old_transactions and self.acks:
                check(self.saved_revalidation or any(record.get('kind') == 1 and
                      bytes.fromhex(record['transaction']) not in self.old_transactions
                      for record in self.received), 'return revalidates with a new transaction')
        return self.counts()

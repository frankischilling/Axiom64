"""Controlled server behavior for manager composition and process-lifetime tests."""
import struct
from dhcp_peer import Peer, check, checksum


class ManagerPeer(Peer):
    def __init__(self, lane, scenario):
        super().__init__(lane)
        self.scenario = scenario
        if scenario.startswith('persist-'):
            # Saved-state checks complete within 120 s; lease renewal is a separate fixture.
            self.lease_timers = self.rebound_timers = (300, 150, 262)
        self.reboots = self.conflicts = 0

    def send(self, frame):
        if self.scenario == 'missing' and self.lane == 0:
            return
        super().send(frame)

    def conflict(self):
        self.conflicts += 1
        arp = bytes.fromhex('0001080006040001') + self.mac + self.address + bytes(6) + self.address
        self.send((bytes([255]) * 6 + self.mac + bytes.fromhex('0806') + arp).ljust(60, b'\0'))

    def packet(self, frame):
        if self.lane == 0 and self.scenario in ('static', 'conflict', 'defense', 'disabled', 'unsafe'):
            check(self.scenario not in ('disabled', 'unsafe'), 'excluded profile emitted traffic')
            check(frame[12:14] == bytes.fromhex('0806'), 'fixed profile never falls back to DHCP')
        # INIT-REBOOT verifies a saved address, with no remembered server/deadline.
        if len(frame) >= 282 and frame[12:14] == bytes.fromhex('0800'):
            ip = frame[14:34]
            total = int.from_bytes(ip[2:4], 'big')
            udp = frame[34:14 + total]
            message = udp[8:]
            options = {}
            at = 240
            while at < len(message):
                code = message[at]
                at += 1
                if code == 255:
                    break
                if not code:
                    continue
                check(at < len(message), 'reboot option header')
                size = message[at]
                at += 1
                check(at + size <= len(message) and code not in options, 'reboot option bounds')
                options[code] = message[at:at + size]
                at += size
            if options.get(53) == b'\x03' and 50 in options and 54 not in options:
                check((self.scenario in ('restart', 'persist-reboot') or
                       self.scenario == 'hint-remove' and self.lane == 0) and
                      ip[0] == 0x45 and ip[9] == 17 and
                      checksum(ip) == 0 and ip[12:20] == bytes(4) + bytes([255]) * 4 and
                      frame[6:12] == self.guest and udp[:4] == struct.pack('!HH', 68, 67) and
                      int.from_bytes(udp[4:6], 'big') == len(udp) and
                      checksum(ip[12:20] + bytes([0, 17]) + struct.pack('!H', len(udp)) + udp) == 0 and
                      message[:3] == bytes([1, 1, 6]) and message[12:16] == bytes(4) and
                      message[28:34] == self.guest and options[50] == self.address and
                      options.get(61) == b'\x01' + self.guest,
                      'independent INIT-REBOOT packet/source/identity/checksum')
                self.reboots += 1
                self.transaction = message[4:8]
                self.answer(5, self.transaction, changed=self.scenario == 'persist-reboot')
                return
        previous = self.probes, self.announcements
        super().packet(frame)
        if self.lane == 0 and self.scenario == 'conflict' and self.probes > previous[0] and not self.conflicts:
            self.conflict()
        if self.lane == 0 and self.scenario == 'defense' and self.announcements > previous[1]:
            if self.announcements == 2 or self.announcements == 3:
                self.conflict()

    def verify(self):
        if self.scenario == 'concurrent':
            return super().verify()
        if self.lane == 0 and self.scenario in ('disabled', 'unsafe'):
            check(not any(getattr(self, name) for name in ('discovers', 'probes', 'announcements', 'releases')),
                  'excluded interface remains silent')
        elif self.lane == 0 and self.scenario in ('static', 'conflict', 'defense'):
            check(not self.discovers and not self.selecting and not self.releases,
                  'static profile has no DHCP acquisition/release')
            expected = {'static': (3, 2, 0), 'conflict': (1, 0, 1), 'defense': (3, 3, 2)}[self.scenario]
            check((self.probes, self.announcements, self.conflicts) == expected,
                  'wire static probe/announce/defense/relinquish counts')
        elif self.lane == 0 and self.scenario == 'missing':
            check(self.discovers >= 1 and not self.selecting and not self.probes and not self.releases,
                  'missing peer remains an independent unconfigured client')
        elif self.lane == 0 and self.scenario == 'manual':
            check(self.discovers >= 2 and self.selecting >= 1 and self.probes >= 3 and
                  not self.announcements and not self.releases,
                  'manual address survives rejected installation without claiming ownership')
        elif self.lane == 0 and self.scenario in ('hint-sync', 'resolver'):
            check(self.discovers >= 2 and self.selecting >= 1 and self.probes >= 3 and
                  not self.announcements and not self.releases,
                  'failed installation rolls back before announcing or releasing an unaccepted lease')
        elif self.scenario in ('hint-remove', 'close'):
            check(self.selecting == (1 if self.scenario == 'hint-remove' and self.lane == 0 else 2) and
                  self.reboots == int(self.scenario == 'hint-remove' and self.lane == 0) and
                  self.probes == 6 and self.releases == 2,
                  f'error exit followed by normal process restart: {self.counts()}')
        elif self.scenario == 'restart':
            check(self.reboots == 1 and self.selecting == 1 and self.probes == 6 and self.releases == 1,
                  'new actual process revalidates hints and probes before reacquisition')
        elif self.scenario == 'persist-prime':
            check(self.discovers == 2 and self.selecting == 1 and self.probes == 3 and
                  self.announcements == 2 and not self.releases and not self.reboots and
                  not self.renewals and not self.rebindings,
                  'first boot synchronizes hints and dies without lease release')
        elif self.scenario == 'persist-reboot':
            check(not self.discovers and not self.selecting and self.reboots == 1 and
                  self.probes == 3 and self.announcements == 2 and self.releases == 1 and
                  not self.renewals and not self.rebindings,
                  'new kernel revalidates persistent hints before installing fresh ACK metadata')
        else:
            check(self.discovers == 2 and self.selecting == 1 and self.probes == 3 and self.releases == 1,
                  f'healthy concurrent adapter completes acquisition and signal release: {self.counts()}')
        return self.counts()

    def counts(self):
        result = {name: getattr(self, name) for name in
                ('discovers', 'selecting', 'renewals', 'rebindings', 'releases', 'probes', 'announcements',
                 'resolutions', 'reboots', 'conflicts')}
        if self.scenario.startswith('persist-'):
            result['transaction'] = self.transaction.hex() if self.transaction else None
        return result

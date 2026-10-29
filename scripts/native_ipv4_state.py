# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain read-only Linux counters without replacing protocol or packet evidence."""
import hashlib
import json
from pathlib import Path
import time


FILES = ('net/snmp', 'net/netstat', 'net/sockstat', 'net/softnet_stat',
         'net/route', 'net/arp', 'meminfo', 'uptime',
         *('sys/net/ipv4/' + name for name in (
             'ipfrag_time', 'ipfrag_high_thresh', 'ipfrag_low_thresh', 'ipfrag_max_dist',
             'icmp_ratelimit', 'icmp_ratemask', 'icmp_msgs_per_sec', 'icmp_msgs_burst',
             'icmp_errors_use_inbound_ifaddr', 'route/mtu_expires',
             'conf/all/rp_filter', 'conf/default/rp_filter')))


def clock_pair():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    return dict(monotonic_ns=before, realtime_ns=realtime,
                monotonic_after_ns=time.monotonic_ns())


class NativeIpv4State:
    def __init__(self, directory, *, proc=Path('/proc')):
        self.proc = Path(proc)
        self.path = Path(directory) / 'native-kernel-state.jsonl'
        self.output = self.path.open('x')
        self.records = 0
        self.read_errors = 0

    def snapshot(self, reason):
        row = dict(record=self.records, reason=reason, clock_begin=clock_pair(),
                   files={}, read_errors={}, read_only=True, counters_not_atomic=True)
        for name in FILES:
            try:
                with (self.proc / name).open('rb') as source:
                    data = source.read(262145)
                if len(data) > 262144:
                    raise ValueError('counter file exceeds retained snapshot bound')
                row['files'][name] = data.decode('ascii')
            except (OSError, ValueError) as error:
                row['read_errors'][name] = dict(type=type(error).__name__,
                                               errno=getattr(error, 'errno', None), message=str(error))
        row['clock_end'] = clock_pair()
        self.output.write(json.dumps(row, separators=(',', ':')) + '\n')
        self.output.flush()
        self.records += 1
        self.read_errors += len(row['read_errors'])

    def close(self):
        self.output.close()
        return dict(path=self.path.name, records=self.records, read_errors=self.read_errors,
                    sha256=hashlib.sha256(self.path.read_bytes()).hexdigest(),
                    read_only=True, diagnostic_only=True, original_packet_clocks_unchanged=True,
                    complete=self.records > 0 and self.read_errors == 0)

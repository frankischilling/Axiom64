# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind the Linux reference's DAD allowance to its recorded timer configuration."""
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import platform
import re
import time

KERNEL = '6.17.0-1022-azure'
CONFIG = 'native-timer-config.txt'
VALUES = 'native-timer-values.json'
EXPECTED = {'/proc/sys/net/ipv6/idgen_delay': '1\n'}
for lane in range(2):
    for name, value in (('router_solicitation_delay', 1000), ('dad_transmits', 1),
                        ('enhanced_dad', 1)):
        EXPECTED[f'/proc/sys/net/ipv6/conf/eth{lane}/{name}'] = str(value)+'\n'
    EXPECTED[f'/proc/sys/net/ipv6/neigh/eth{lane}/retrans_time_ms'] = '1000\n'


def require(value, reason):
    if not value:
        raise ValueError('native DAD timer policy: '+reason)


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def configuration(data):
    require(len(data) <= 1048576, 'bounded original kernel configuration')
    text = data.decode()
    require(re.findall(r'^CONFIG_HZ=(\d+)$', text, re.MULTILINE) == ['1000'] and
            re.search(r'^CONFIG_64BIT=y$', text, re.MULTILINE),
            'verified Linux 6.17 x86-64 CONFIG_HZ=1000')


@lru_cache(maxsize=1)
def upper_microseconds():
    # Linux v6.17 groups timer-list expirations in 64 buckets per level, with
    # eight times coarser ticks per level. Delayed DAD work uses this timer
    # wheel; its configured protocol delays do not include the bucket padding.
    def expiry(now, delay):
        if not delay:
            return now
        granularity = 1 if delay < 63 else 8 if delay < 504 else 64
        return ((now+delay)//granularity+1)*granularity
    maximum = 0
    for phase in range(64):
        first = expiry(phase, 1000)
        for initial_delay in range(1000):
            last = expiry(expiry(first, initial_delay), 1000)
            maximum = max(maximum, last-phase)
    require(maximum == 3112, 'complete default DAD timer schedule')
    # Retain the original 100 ms observer allowance after the native timer
    # schedule. The guest continues to use its original 3.1-second ceiling.
    return (maximum+100)*1000


def sample():
    before = time.monotonic_ns()
    values = {name:Path(name).read_text() for name in EXPECTED}
    after = time.monotonic_ns()
    require(values == EXPECTED, 'unchanged original DAD and neighbor parameters')
    return dict(begin_ns=before, end_ns=after, values=values)


def begin(directory):
    if platform.release() != KERNEL:
        return None
    path = Path('/boot/config-'+KERNEL)
    data = path.read_bytes() if path.exists() else gzip.decompress(Path('/proc/config.gz').read_bytes())
    configuration(data)
    (directory/CONFIG).write_bytes(data)
    return dict(schema=1, kernel=KERNEL, config_sha256=fingerprint(data), before=sample())


def finish(directory, started):
    if started is None:
        return None
    require(platform.release() == started['kernel'] == KERNEL, 'same original running kernel')
    values = dict(before=started['before'], after=sample())
    data = (json.dumps(values, sort_keys=True, indent=2)+'\n').encode()
    (directory/VALUES).write_bytes(data)
    policy = dict(schema=1, kernel=KERNEL, config_sha256=started['config_sha256'],
                  values_sha256=fingerprint(data), upper_us=upper_microseconds())
    (directory/'native-timer-policy.json').write_text(json.dumps(policy,indent=2)+'\n')
    return policy


def inspect(directory, policy, kernel, first_ns, last_ns):
    require(isinstance(policy, dict) and set(policy) ==
            {'schema','kernel','config_sha256','values_sha256','upper_us'}, 'complete recorded policy')
    require(type(policy['schema']) is int and policy['schema'] == 1 and policy['kernel'] == kernel == KERNEL,
            'actual supported native reference kernel')
    for name, key in ((CONFIG,'config_sha256'), (VALUES,'values_sha256')):
        path = directory/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576,
                'bounded original '+name)
        require(fingerprint(path.read_bytes()) == policy[key], 'original '+name+' fingerprint')
    configuration((directory/CONFIG).read_bytes())
    values = json.loads((directory/VALUES).read_text())
    require(set(values) == {'before','after'}, 'both actual parameter observations')
    for name in values:
        row = values[name]
        require(set(row) == {'begin_ns','end_ns','values'} and row['values'] == EXPECTED and
                type(row['begin_ns']) is int and type(row['end_ns']) is int and
                0 < row['begin_ns'] <= row['end_ns'], 'exact original '+name+' parameters')
    require(values['before']['end_ns'] < first_ns <= last_ns < values['after']['begin_ns'],
            'actual parameter observations bracket the complete C workload')
    require(type(policy['upper_us']) is int and policy['upper_us'] == upper_microseconds(),
            'source-derived native timer and observer allowance')
    return policy['upper_us']

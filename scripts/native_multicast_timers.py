# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify native IGMP query timers against the recorded Linux configuration."""
from functools import lru_cache
import gzip
import hashlib
from pathlib import Path
import platform
import time

from native_ipv6_timers import SUPPORTED_KERNELS, configuration

CONFIG = 'native-multicast-config.txt'
AFTER_CONFIG = 'native-multicast-config-after.txt'


def require(value, reason):
    if not value:
        raise ValueError('native multicast timer policy: '+reason)


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


@lru_cache(maxsize=1)
def upper_microseconds():
    # The captured query advertises one second. Linux's IGMP timer adds two
    # jiffies to a random delay below that limit, then the timer wheel rounds
    # expiry up to its bucket. Preserve the original 10 ms observer allowance.
    maximum = 0
    for phase in range(64):
        for random_delay in range(1000):
            delay = random_delay+2
            granularity = 1 if delay < 63 else 8 if delay < 504 else 64
            expiry = ((phase+delay)//granularity+1)*granularity
            maximum = max(maximum, expiry-phase)
    require(maximum == 1065, 'complete one-second query schedule')
    return (maximum+10)*1000


def read_configuration(kernel):
    path = Path('/boot/config-'+kernel)
    return path.read_bytes() if path.exists() else gzip.decompress(Path('/proc/config.gz').read_bytes())


def begin(directory):
    kernel = platform.release()
    if kernel not in SUPPORTED_KERNELS:
        return None
    stamp = time.monotonic_ns()
    data = read_configuration(kernel)
    (directory/CONFIG).write_bytes(data)
    configuration(data)
    return dict(kernel=kernel, config_sha256=fingerprint(data), before_ns=stamp)


def finish(directory, started):
    if started is None:
        return None
    require(platform.release() == started['kernel'] and started['kernel'] in SUPPORTED_KERNELS,
            'same actual running kernel')
    data = read_configuration(started['kernel'])
    (directory/AFTER_CONFIG).write_bytes(data)
    configuration(data)
    require(fingerprint(data) == started['config_sha256'], 'unchanged actual kernel configuration')
    return dict(schema=1, **started, after_ns=time.monotonic_ns(), upper_us=upper_microseconds())


def inspect(directory, policy, kernel, statistics):
    require(isinstance(policy, dict) and set(policy) ==
            {'schema','kernel','config_sha256','before_ns','after_ns','upper_us'}, 'complete recorded policy')
    require(type(policy['schema']) is int and policy['schema'] == 1 and
            policy['kernel'] == kernel and kernel in SUPPORTED_KERNELS, 'actual supported reference kernel')
    for name in (CONFIG, AFTER_CONFIG):
        path = directory/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576,
                'bounded original '+name)
        data = path.read_bytes()
        require(fingerprint(data) == policy['config_sha256'], 'original '+name+' fingerprint')
        configuration(data)
    require(type(policy['before_ns']) is int and type(policy['after_ns']) is int and
            0 < policy['before_ns'] < policy['after_ns'], 'actual monotonic observation bounds')
    require(isinstance(statistics, list) and len(statistics) == 2, 'both actual capture intervals')
    for row in statistics:
        first = row['clock_start']['receipt_monotonic_ns']
        last = row['clock_end']['receipt_monotonic_after_ns']
        require(type(first) is int and type(last) is int and
                policy['before_ns'] < first <= last < policy['after_ns'],
                'configuration observations bracket every actual capture')
    require(type(policy['upper_us']) is int and policy['upper_us'] == upper_microseconds(),
            'source-derived native query and observer allowance')
    return policy['upper_us']

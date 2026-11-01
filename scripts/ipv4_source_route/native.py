# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain native timer policy, interface state and independent packet ingress."""
import gzip
import json
from pathlib import Path
import platform
import re
import struct
import subprocess
import time

from ipv4_source_route.controls import decode, require
from ipv4_source_route.packets import CLOCK_BOUND_NS
from tcp6.inputs import digest, write

INTERFACES = ('eth0', 'peer0', 'eth1', 'peer1')
NEIGHBOR = dict(retrans_time_ms=1000, mcast_solicit=3, ucast_solicit=3, app_solicit=0)
PRECISION_NS = 20000000


def configuration(data):
    require(len(data) <= 1048576, 'bounded actual native kernel configuration')
    text = data.decode()
    values = re.findall(r'^CONFIG_HZ=(\d+)$', text, re.M)
    require(len(values) == 1 and int(values[0]) in (100, 250, 300, 1000) and
            re.search(r'^CONFIG_64BIT=y$', text, re.M), 'actual supported x86-64 native timer frequency')
    return int(values[0])


def policy():
    before = time.monotonic_ns()
    values = {name: {key: int((Path('/proc/sys/net/ipv4/neigh') / name / key).read_text())
                     for key in NEIGHBOR} for name in INTERFACES}
    after = time.monotonic_ns()
    require(all(value == NEIGHBOR for value in values.values()), 'original one-second three-probe native ARP policy')
    return dict(begin_ns=before, end_ns=after, interfaces=values)


def begin(directory):
    kernel = platform.release()
    path = Path('/boot/config-' + kernel)
    data = path.read_bytes() if path.exists() else gzip.decompress(Path('/proc/config.gz').read_bytes())
    hz = configuration(data)
    (directory / 'native-kernel-config.txt').write_bytes(data)
    value = dict(kernel=kernel, config_sha256=digest(directory / 'native-kernel-config.txt'), hz=hz, before=policy())
    write(directory / 'native-timer-policy.json', value)
    return value


def finish(directory, original):
    require(platform.release() == original['kernel'], 'same actual native kernel throughout capture')
    value = dict(original, after=policy())
    write(directory / 'native-timer-policy.json', value)


def maximum_interval_ns(hz):
    # The Linux timer wheel uses 64 buckets and eight times coarser ticks at
    # each level. Derive its maximum rounding for the recorded one-second delay.
    granularity = 1 if hz < 63 else 8 if hz < 504 else 64
    ticks = max(((phase + hz) // granularity + 1) * granularity - phase
                for phase in range(granularity))
    return (ticks * 1000000000 + hz - 1) // hz


def bounds(directory):
    value = decode((directory / 'native-timer-policy.json').read_text())
    hz = configuration((directory / 'native-kernel-config.txt').read_bytes())
    require(re.search(r'^IPV4_SOURCE_WIRE_KERNEL version=2 sysname=Linux release=' + re.escape(value['kernel']) + r' cases=\d+$',
                      (directory / 'client.log').read_text(), re.M), 'actual running native kernel matches retained configuration')
    require(type(value['hz']) is int and value['hz'] == hz and value['config_sha256'] ==
            digest(directory / 'native-kernel-config.txt'), 'actual native configuration and timer policy binding')
    for phase in ('before', 'after'):
        sample = value[phase]
        require(set(sample['interfaces']) == set(INTERFACES) and
                all(set(row) == set(NEIGHBOR) and all(type(item) is int for item in row.values()) and row == NEIGHBOR
                    for row in sample['interfaces'].values()) and
                type(sample['begin_ns']) is int and type(sample['end_ns']) is int and
                0 <= sample['begin_ns'] <= sample['end_ns'], 'unchanged actual native neighbor parameters')
    require(value['before']['end_ns'] <= value['after']['begin_ns'], 'ordered native timer configuration readbacks')
    results = decode((directory / 'results.json').read_text())
    require(type(results) is list and results and
            value['before']['end_ns'] <= results[0]['input_began_ns'] and
            results[-1]['ended_ns'] <= value['after']['begin_ns'],
            'actual native timer policy samples enclose the complete capture')
    return 1000000000 - PRECISION_NS, maximum_interval_ns(hz) + CLOCK_BOUND_NS + PRECISION_NS


def state(case, phase):
    import fcntl
    import socket
    before = time.monotonic_ns()
    links = {}
    # The inherited sysfs mount can describe the parent network namespace.
    # Ioctls and netlink observe the actual private namespace of this process.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        for name in INTERFACES:
            request = struct.pack('16s24x', name.encode())
            flags = struct.unpack_from('H', fcntl.ioctl(control.fileno(), 0x8913, request), 16)[0]
            links[name] = dict(flags=flags, index=socket.if_nametoindex(name))
    controls = {name: (Path('/proc/sys/net/ipv4') / name).read_text()
                for name in ('ip_forward', 'conf/all/accept_source_route', 'conf/eth0/accept_source_route',
                             'conf/eth1/accept_source_route', 'conf/eth0/forwarding', 'conf/eth1/forwarding')}
    netlink = {}
    for name, arguments in dict(link=('link', 'show'), address=('address', 'show'), route=('route', 'show', 'table', 'all'),
                                rule=('rule', 'show'), neighbor=('neighbor', 'show')).items():
        netlink[name] = json.loads(subprocess.check_output(['ip', '-j', '-details', *arguments], text=True))
    return dict(case=case, phase=phase, begin_ns=before, end_ns=time.monotonic_ns(), links=links,
                controls=controls, netlink=netlink, snmp=Path('/proc/net/snmp').read_text(),
                netstat=Path('/proc/net/netstat').read_text())


def ingress(directory):
    wire = decode((directory / 'wire.json').read_text())
    observed = decode((directory / 'ingress-wire.json').read_text())
    require(type(observed) is list, 'independent native ingress observation stream')
    expected = [(value['case'], value['index'], value['frame']) for value in wire
                if value['direction'] == 'input' and value['frame'][24:28] == '0800']
    actual = []
    previous = -1
    for value in observed:
        require(set(value) == {'case', 'index', 'frame', 'monotonic_ns', 'realtime_ns', 'packet_type'} and
                type(value['case']) is int and type(value['index']) is int and value['index'] in (0, 1) and
                type(value['monotonic_ns']) is int and value['monotonic_ns'] >= previous and
                type(value['realtime_ns']) is int and type(value['packet_type']) is int and
                0 <= value['packet_type'] <= 4, 'complete ordered native ingress monitor metadata')
        previous = value['monotonic_ns']
        frame = bytes.fromhex(value['frame'])
        require(len(frame) >= 14, 'complete ingress Ethernet header')
        if value['packet_type'] != 4 and frame[12:14] == b'\x08\x00':
            actual.append((value['case'], value['index'], value['frame']))
    require(actual == expected, 'every sent IPv4 frame independently observed at the native receiving interface')
    statistics = decode((directory / 'ingress-statistics.json').read_text())
    require(set(statistics) == {'0', '1'} and all(type(row['drops']) is int and row['drops'] == 0
            for row in statistics.values()), 'zero independent native ingress capture drops')
    results = decode((directory / 'results.json').read_text())
    states = decode((directory / 'native-state.json').read_text())
    require([(value['case'], value['phase']) for value in states] ==
            [(number, phase) for number in range(len(results)) for phase in ('ready', 'after')],
            'complete actual pre-input and post-observation native state')
    def counter(text):
        lines = text.splitlines()
        for index in range(len(lines) - 1):
            if lines[index].startswith('Ip: ') and 'InReceives' in lines[index]:
                names, values = lines[index].split()[1:], lines[index + 1].split()[1:]
                require(lines[index + 1].startswith('Ip: ') and len(names) == len(values), 'complete original native IP counters')
                return int(values[names.index('InReceives')])
        raise ValueError('missing actual native IP receive counter')
    for number, result in enumerate(results):
        before, after = states[number * 2:number * 2 + 2]
        require(type(before['begin_ns']) is int and type(before['end_ns']) is int and
                type(after['begin_ns']) is int and type(after['end_ns']) is int and
                before['begin_ns'] <= before['end_ns'] <= result['input_began_ns'] and
                result['ended_ns'] <= after['begin_ns'] <= after['end_ns'], 'actual native state brackets the complete packet observation')
        require(set(before['links']) == set(INTERFACES) and all(type(value['flags']) is int and
                value['flags'] & 1 and type(value['index']) is int and value['index'] > 0
                for value in before['links'].values()), 'actual configured native interfaces are administratively up')
        local = [value for value in wire if value['case'] == number and value['direction'] == 'input' and
                 value['frame'][24:28] == '0800' and value['frame'][:12] == bytes((2, 0, 0, 0, 0, value['index'] + 1)).hex()]
        require(counter(after['snmp']) - counter(before['snmp']) >= len(local),
                'actual native IP receive counters include every locally addressed test input')
    return len(actual)

# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain actual Linux 6.6 global ICMP controls across private namespaces."""
import fcntl
import json
import os
from pathlib import Path
import platform
import re
import stat
import time


LIMITS = {'icmp_msgs_per_sec': '1000\n', 'icmp_msgs_burst': '50\n'}
PROC = Path('/proc/sys/net/ipv4')


def require(value, reason):
    if not value:
        raise ValueError('native ICMP policy: ' + reason)


def read_handle(descriptor, name, opened_namespace):
    require(name in LIMITS and type(descriptor) is int and descriptor >= 3,
            'one original global control descriptor')
    path = str(PROC / name)
    metadata = os.fstat(descriptor)
    require(stat.S_ISREG(metadata.st_mode) and
            fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY and
            os.readlink('/proc/self/fd/' + str(descriptor)) == path,
            'original read-only procfs control handle')
    data = os.pread(descriptor, 64, 0)
    require(0 < len(data) < 64, 'bounded complete global policy observation')
    source = dict(scope='global', path=path, open_namespace=opened_namespace,
                  read_namespace=os.readlink('/proc/self/ns/net'), inode=metadata.st_ino,
                  read_only=True)
    return data, source


class InitialIcmpLimits:
    """Own initial-namespace handles until all native children have completed."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.path = None
        self.descriptors = {}

    @property
    def pass_fds(self):
        return tuple(self.descriptors.values())

    def __enter__(self):
        if not platform.release().startswith('6.6.'):
            return self
        self.namespace = os.readlink('/proc/self/ns/net')
        self.kernel = platform.release()
        try:
            for name in LIMITS:
                self.descriptors[name] = os.open(PROC / name, os.O_RDONLY | os.O_CLOEXEC)
            values = {name: read_handle(fd, name, self.namespace)[0].decode('ascii')
                      for name, fd in self.descriptors.items()}
            require(values == LIMITS, 'original default global rate controls')
            self.path = self.directory / 'global-rate-handles.json'
            self.path.write_text(json.dumps(dict(schema=1, kernel=self.kernel,
                namespace=self.namespace, descriptors=self.descriptors,
                initial_values=values, monotonic_ns=time.monotonic_ns()), indent=2))
            return self
        except BaseException:
            for descriptor in self.descriptors.values():
                os.close(descriptor)
            raise

    def __exit__(self, kind, value, traceback):
        if self.path is None:
            return
        try:
            values = {name: read_handle(fd, name, self.namespace)[0].decode('ascii')
                      for name, fd in self.descriptors.items()}
            record = dict(schema=1, kernel=self.kernel, namespace=self.namespace,
                          final_values=values, monotonic_ns=time.monotonic_ns(),
                          unchanged=values == LIMITS, read_only=True)
            (self.directory / 'global-rate-final.json').write_text(json.dumps(record, indent=2))
            require(record['unchanged'], 'global controls remain unchanged after native children')
        finally:
            for descriptor in self.descriptors.values():
                os.close(descriptor)


class InheritedIcmpLimits:
    def __init__(self, path):
        path = Path(path)
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4096,
                'bounded original global handle record')
        record = json.loads(path.read_text())
        require(set(record) == {'schema', 'kernel', 'namespace', 'descriptors', 'initial_values', 'monotonic_ns'} and
                type(record['schema']) is int and record['schema'] == 1 and
                record['kernel'] == platform.release() and record['kernel'].startswith('6.6.') and
                isinstance(record['namespace'], str) and re.fullmatch(r'net:\[\d+\]', record['namespace']) and
                record['namespace'] != os.readlink('/proc/self/ns/net') and
                set(record['descriptors']) == set(LIMITS) and record['initial_values'] == LIMITS,
                'actual supported global policy and distinct private namespace')
        self.descriptors = record['descriptors']
        self.namespace = record['namespace']
        self.kernel = record['kernel']
        for name in LIMITS:
            self.read(name)

    def read(self, name):
        require(not (PROC / name).exists(), 'global fallback only for absent private-namespace controls')
        return read_handle(self.descriptors[name], name, self.namespace)

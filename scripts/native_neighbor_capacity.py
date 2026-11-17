# SPDX-License-Identifier: GPL-3.0-or-later
"""Reserve bounded shared IPv6 neighbor capacity for an owned native cohort."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import threading
import time


STAT_PATH = Path('/proc/net/stat/ndisc_cache')
SETTINGS_PATH = Path('/proc/sys/net/ipv6/neigh/default')
SELF_NAMESPACE = Path('/proc/self/ns/net')
INITIAL_NAMESPACE = Path('/proc/1/ns/net')
LOCK_PATH = Path('/run/lock/axiom64-native-neighbor-capacity.lock')
SETTINGS = ('gc_thresh1', 'gc_thresh2', 'gc_thresh3', 'gc_interval',
            'base_reachable_time_ms', 'retrans_time_ms', 'gc_stale_time', 'delay_first_probe_time')
HEADROOM_PER_PROFILE = 1024
MAX_CAPACITY = 1 << 20


class CapacityError(RuntimeError):
    pass


def parse_statistics(raw):
    """The entries column repeats a shared count; other columns are per CPU."""
    if len(raw) > 1 << 20:
        raise CapacityError('neighbor statistics exceed the bounded input size')
    lines = raw.splitlines()
    if not 2 <= len(lines) <= 4097:
        raise CapacityError('neighbor statistics require a bounded CPU inventory')
    fields = lines[0].split()
    if (not 3 <= len(fields) <= 64 or len(set(fields)) != len(fields) or
            not {'entries', 'table_fulls', 'forced_gc_runs'} <= set(fields)):
        raise CapacityError('neighbor statistics have an unsupported header')
    rows = []
    for line in lines[1:]:
        words = line.split()
        if len(words) != len(fields) or any(not re.fullmatch(r'[0-9a-fA-F]{1,16}', word)
                                          for word in words):
            raise CapacityError('neighbor statistics contain an invalid CPU row')
        row = dict(zip(fields, (int(word, 16) for word in words)))
        if row['entries'] > 0xffffffff:
            raise CapacityError('neighbor entries exceed the kernel counter width')
        rows.append(row)
    return dict(entries=max(row['entries'] for row in rows), cpu_rows=len(rows),
                counters={name: sum(row[name] for row in rows)
                          for name in fields if name != 'entries'})


def _read(path, limit):
    with Path(path).open('r', encoding='ascii') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise CapacityError('neighbor input exceeds its bound: ' + str(path))
    return raw


def _setting(name):
    raw = _read(SETTINGS_PATH / name, 64)
    if not re.fullmatch(r'[0-9]+\n?', raw) or len(raw.strip()) > 10:
        raise CapacityError('invalid neighbor setting: ' + name)
    value = int(raw)
    if value > 0x7fffffff:
        raise CapacityError('neighbor setting exceeds its kernel range: ' + name)
    return raw, value


def _snapshot():
    raw = _read(STAT_PATH, 1 << 20)
    settings = {name: _setting(name) for name in SETTINGS}
    return dict(observed_monotonic_ns=time.monotonic_ns(), statistics_raw=raw,
                statistics=parse_statistics(raw),
                settings_raw={name: row[0] for name, row in settings.items()},
                settings={name: row[1] for name, row in settings.items()})


def _initial_namespace():
    if os.geteuid() != 0:
        raise CapacityError('shared neighbor capacity requires a root parent')
    if threading.current_thread() is not threading.main_thread():
        raise CapacityError('shared neighbor capacity requires the parent main thread')
    current, initial = SELF_NAMESPACE.stat(), INITIAL_NAMESPACE.stat()
    if (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino):
        raise CapacityError('shared neighbor capacity requires the initial network namespace')
    return dict(device=current.st_dev, inode=current.st_ino)


def _lock():
    # Open every directory without following symlinks. A sticky root-owned
    # directory permits the usual /run/lock layout without trusting its users.
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in LOCK_PATH.parent.parts[1:]:
            next_directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC |
                                     os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
            info = os.fstat(directory)
            if info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise CapacityError('neighbor lock directory is not protected by root')
        descriptor = os.open(LOCK_PATH.name, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC |
                             os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                    info.st_mode & 0o077 or info.st_nlink != 1):
                raise CapacityError('neighbor lock must be a private root-owned regular file')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise CapacityError('another native cohort owns shared neighbor capacity') from error
            return descriptor, dict(path=str(LOCK_PATH), device=info.st_dev, inode=info.st_ino)
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(directory)


def _write_capacity(value):
    descriptor = os.open(SETTINGS_PATH / 'gc_thresh3', os.O_WRONLY | os.O_TRUNC |
                         os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = (str(value) + '\n').encode('ascii')
        if os.write(descriptor, raw) != len(raw):
            raise CapacityError('short write while setting shared neighbor capacity')
    finally:
        os.close(descriptor)


def _save(stream, receipt):
    stream.seek(0)
    json.dump(receipt, stream, indent=2)
    stream.write('\n')
    stream.truncate()
    stream.flush()


def _terminate(signum, frame):
    raise CapacityError('SIGTERM interrupted the native neighbor capacity owner')


@contextmanager
def ipv6_neighbor_capacity(output_directory, profile_count):
    """Reserve capacity for all selected profiles and restore the prior hard limit.

    The error cohort has 560 distinct unicast/solicited-multicast test keys per
    profile. Its 1024-entry allowance includes auxiliary traffic and headroom.
    Selected profiles, rather than worker slots, bound delayed reclamation.
    """
    if type(profile_count) is not int or not 1 <= profile_count <= 64:
        raise CapacityError('neighbor capacity requires between 1 and 64 profiles')
    output_directory = Path(output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)
    path = output_directory / 'neighbor-capacity.json'
    receipt = dict(schema=1, profile_count=profile_count, headroom_per_profile=HEADROOM_PER_PROFILE,
                   helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   changed=False, write_attempted=False, body_started=False,
                   body_completed=False, restored=False)
    lock_descriptor = None
    original = target = None
    write_attempted = applied_verified = False
    failure = None
    cleanup_errors = []
    previous_sigterm = None
    signal_installed = False
    with path.open('x+', encoding='utf-8') as stream:
        try:
            receipt['namespace'] = _initial_namespace()
            lock_descriptor, receipt['lock'] = _lock()
            previous_sigterm = signal.signal(signal.SIGTERM, _terminate)
            signal_installed = True
            receipt['sigterm_restoration'] = True
            before = receipt['before'] = _snapshot()
            values = before['settings']
            if not 0 <= values['gc_thresh1'] <= values['gc_thresh2'] <= values['gc_thresh3']:
                raise CapacityError('neighbor thresholds are not ordered')
            original = values['gc_thresh3']
            needed = before['statistics']['entries'] + HEADROOM_PER_PROFILE * profile_count
            if needed > MAX_CAPACITY:
                raise CapacityError('native neighbor reservation exceeds the finite capacity bound')
            target = max(original, needed)
            receipt.update(required_capacity=needed, applied_capacity=target)
            if target != original:
                write_attempted = True
                receipt['write_attempted'] = True
                _write_capacity(target)
                receipt['changed'] = True
            applied = receipt['applied'] = _snapshot()
            if applied['settings']['gc_thresh3'] != target:
                raise CapacityError('shared neighbor capacity write did not read back')
            if any(applied['settings'][name] != values[name] for name in SETTINGS if name != 'gc_thresh3'):
                raise CapacityError('another neighbor setting changed during reservation')
            applied_verified = True
            receipt['body_started'] = True
            _save(stream, receipt)
            yield receipt
            receipt['body_completed'] = True
        except BaseException as error:
            failure = error
            receipt['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            if original is not None:
                try:
                    receipt['final'] = _snapshot()
                    if applied_verified:
                        delta = (receipt['final']['statistics']['counters']['table_fulls'] -
                                 receipt['applied']['statistics']['counters']['table_fulls'])
                        receipt['cohort_table_fulls_delta'] = delta
                        if delta:
                            cleanup_errors.append('shared neighbor table overflow counter changed during the cohort')
                except BaseException as error:
                    cleanup_errors.append('final state: ' + str(error))
                try:
                    current_settings = {name: _setting(name)[1] for name in SETTINGS}
                    current = current_settings['gc_thresh3']
                    expected = target if applied_verified or write_attempted else original
                    if current != expected:
                        if not applied_verified and current == original:
                            receipt['restored'] = True
                        else:
                            raise CapacityError('shared neighbor capacity changed externally; not overwriting it')
                    else:
                        if write_attempted and current != original:
                            if not (current_settings['gc_thresh1'] <= current_settings['gc_thresh2'] <= original):
                                raise CapacityError('external neighbor thresholds prevent ordered capacity restoration; not overwriting them')
                            _write_capacity(original)
                        if _setting('gc_thresh3')[1] != original:
                            raise CapacityError('restored neighbor capacity did not read back')
                        receipt['restored'] = True
                except BaseException as error:
                    cleanup_errors.append('restoration: ' + str(error))
                try:
                    restored = receipt['restored_state'] = _snapshot()
                    unchanged = all(restored['settings'][name] == receipt['before']['settings'][name]
                                    for name in SETTINGS if name != 'gc_thresh3')
                    receipt['other_settings_unchanged'] = unchanged
                    if not unchanged:
                        cleanup_errors.append('another neighbor setting changed during the cohort')
                    initial_counters = receipt['before']['statistics']['counters']
                    for label in ('applied', 'final', 'restored_state'):
                        if label in receipt:
                            receipt[label]['counter_deltas'] = {
                                name: receipt[label]['statistics']['counters'][name] - initial_counters[name]
                                for name in ('table_fulls', 'forced_gc_runs')}
                except BaseException as error:
                    cleanup_errors.append('restored state: ' + str(error))
            receipt['cleanup_errors'] = cleanup_errors
            receipt['passed'] = failure is None and not cleanup_errors and receipt['restored']
            receipt['end_monotonic_ns'] = time.monotonic_ns()
            try:
                _save(stream, receipt)
            finally:
                if lock_descriptor is not None:
                    os.close(lock_descriptor)
                if signal_installed:
                    signal.signal(signal.SIGTERM, previous_sigterm)
    if cleanup_errors:
        raise CapacityError('; '.join(cleanup_errors)) from failure
    if failure is not None:
        raise failure

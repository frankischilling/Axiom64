# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded disposable NBD backend with observed write/flush fault boundaries.

This is a test device, not a production logging hook.  Writethrough persists
individual requests; writeback keeps an explicitly volatile sector cache until
an actual flush.  Neither model repairs filesystem bytes or flushes on close.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import time

API_VERSION = 2
SECTOR = 512
CACHE_LIMIT = 16 * 1024 * 1024
REQUEST_LIMIT = 4096
TRACE_LIMIT = 64 * 1024 * 1024
_settings = {}
_trace = None
_opened = False
_armed = False
_arm_pending = False
_hit = False
_counts = {'request': 0, 'write': 0, 'flush': 0}
_durable_generation = 0


def backend_command(disk, socket, trace, *, control_offset, control_marker, control_end_marker=None,
                    cache_model='writeback', fault_operation='write',
                    fault_request=0, fault_mode='observe', gate=None):
    """Return an explicit nbdkit command; callers own its process and files."""
    values = {'disk': str(Path(disk).resolve()), 'trace': str(Path(trace).resolve()),
              'control-offset': str(control_offset), 'control-marker': control_marker.hex(),
              'control-end-marker': control_end_marker.hex() if control_end_marker else '',
              'cache-model': cache_model, 'fault-operation': fault_operation,
              'fault-request': str(fault_request), 'fault-mode': fault_mode,
              'gate': str(Path(gate).resolve()) if gate else ''}
    return ['nbdkit', '-f', '--exit-with-parent', '-U', str(socket), 'python',
            str(Path(__file__).resolve()), *(key + '=' + value for key, value in values.items())]


def trace_events(path, *, complete=True):
    path = Path(path)
    if not path.exists():
        return []
    if path.stat().st_size > TRACE_LIMIT:
        raise RuntimeError('block trace exceeds its explicit bound')
    data = path.read_bytes()
    if data and not data.endswith(b'\n'):
        if complete:
            raise RuntimeError('block trace has a partial terminal record')
        data = data.rsplit(b'\n', 1)[0] + b'\n' if b'\n' in data else b''
    return [json.loads(line) for line in data.splitlines()]


def config(key, value):
    if key not in {'disk', 'trace', 'control-offset', 'control-marker', 'control-end-marker', 'cache-model',
                   'fault-operation', 'fault-request', 'fault-mode', 'gate'} or key in _settings:
        raise ValueError('unknown or repeated block backend setting: ' + key)
    _settings[key] = value


def config_complete():
    global _trace
    _settings.setdefault('control-end-marker', '')
    if set(_settings) != {'disk', 'trace', 'control-offset', 'control-marker', 'control-end-marker', 'cache-model',
                          'fault-operation', 'fault-request', 'fault-mode', 'gate'}:
        raise ValueError('every bounded block backend setting must be explicit')
    for key in ('disk', 'trace'):
        path = Path(_settings[key])
        if not path.is_absolute() or path.is_symlink() or path.parent.is_symlink():
            raise ValueError('block paths must be absolute and have no symlink leaf')
    disk = Path(_settings['disk']).stat()
    if not stat.S_ISREG(disk.st_mode) or disk.st_nlink != 1 or not disk.st_size or disk.st_size % SECTOR:
        raise ValueError('block source must be a single-link regular sector-aligned file')
    _settings['control-offset'] = int(_settings['control-offset'])
    _settings['control-marker'] = bytes.fromhex(_settings['control-marker'])
    _settings['control-end-marker'] = bytes.fromhex(_settings['control-end-marker'])
    _settings['fault-request'] = int(_settings['fault-request'])
    if (_settings['control-offset'] < 0 or _settings['control-offset'] % SECTOR or
            _settings['control-offset'] + SECTOR > disk.st_size or
            not 1 <= len(_settings['control-marker']) <= 64 or
            len(_settings['control-end-marker']) > 64 or
            (_settings['control-end-marker'] and
             (_settings['control-end-marker'].startswith(_settings['control-marker']) or
              _settings['control-marker'].startswith(_settings['control-end-marker']))) or
            _settings['cache-model'] not in ('writeback', 'writethrough') or
            _settings['fault-operation'] not in ('write', 'flush') or
            _settings['fault-mode'] not in ('observe', 'eio', 'pause-before', 'pause-after') or
            not 0 <= _settings['fault-request'] <= REQUEST_LIMIT or
            ((_settings['fault-mode'] == 'observe') != (_settings['fault-request'] == 0))):
        raise ValueError('invalid bounded block backend policy')
    gate = _settings['gate']
    if gate and (not Path(gate).is_absolute() or Path(gate).exists() or Path(gate).is_symlink()):
        raise ValueError('the optional pause release file must be fresh and absolute')
    if _settings['fault-mode'].startswith('pause-') and not gate:
        raise ValueError('a pause needs an explicit owned release path')
    _trace = os.open(_settings['trace'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    _emit('configured', cache_model=_settings['cache-model'], cache_limit=CACHE_LIMIT,
          request_limit=REQUEST_LIMIT, source_bytes=disk.st_size)


def thread_model():
    import nbdkit
    return nbdkit.THREAD_MODEL_SERIALIZE_ALL_REQUESTS


def _emit(event, **fields):
    row = dict(event=event, monotonic_ns=time.monotonic_ns(), armed=_armed,
               durable_generation=_durable_generation, **fields)
    data = (json.dumps(row, sort_keys=True) + '\n').encode()
    if os.fstat(_trace).st_size + len(data) > TRACE_LIMIT:
        raise RuntimeError('block trace exceeds its explicit bound')
    _write(_trace, data)
    os.fsync(_trace)


def _write(fd, data, offset=None):
    done = 0
    while done < len(data):
        count = os.write(fd, data[done:]) if offset is None else os.pwrite(fd, data[done:], offset + done)
        if count <= 0:
            raise OSError(errno.EIO, 'short disposable backend write')
        done += count


def _digest(handle):
    value = hashlib.sha256()
    offset = 0
    while data := os.pread(handle['fd'], 1024 * 1024, offset):
        value.update(data)
        offset += len(data)
    return value.hexdigest()


def open(readonly):
    global _opened
    if _opened or readonly:
        raise RuntimeError('the fault device permits one writable connection')
    fd = os.open(_settings['disk'], os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    value = os.fstat(fd)
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        os.close(fd)
        raise RuntimeError('the disposable disk changed before open')
    _opened = True
    return dict(fd=fd, pending={})


def close(handle):
    _emit('closed', discarded_volatile_bytes=len(handle['pending']) * SECTOR,
          disk_sha256=_digest(handle), requests=dict(_counts), fault_hit=_hit)
    handle['pending'].clear()
    os.close(handle['fd'])


def get_size(handle):
    return os.fstat(handle['fd']).st_size


def block_size(handle):
    return SECTOR, 1024, 1024 * 1024


def can_write(handle):
    return True


def can_flush(handle):
    return True


def can_multi_conn(handle):
    return False


def can_fua(handle):
    import nbdkit
    return nbdkit.FUA_NONE


def _range(handle, length, offset):
    if offset < 0 or offset % SECTOR or length % SECTOR or offset + length > get_size(handle):
        raise OSError(errno.EINVAL, 'request lies outside the aligned disposable device')


def pread(handle, buffer, offset, flags):
    _range(handle, len(buffer), offset)
    data = bytearray(os.pread(handle['fd'], len(buffer), offset))
    if len(data) != len(buffer):
        raise OSError(errno.EIO, 'short disposable backend read')
    for position in range(0, len(data), SECTOR):
        if offset + position in handle['pending']:
            data[position:position + SECTOR] = handle['pending'][offset + position]
    buffer[:] = data


def _request(handle, operation, **fields):
    global _hit
    if not _armed:
        return None, False
    _counts['request'] += 1
    _counts[operation] += 1
    if _counts['request'] > REQUEST_LIMIT:
        raise RuntimeError('armed requests exceed their explicit bound')
    row = dict(operation=operation, request=_counts['request'], index=_counts[operation], **fields)
    _emit('request', **row)
    selected = (not _hit and operation == _settings['fault-operation'] and
                _counts[operation] == _settings['fault-request'])
    if selected:
        _hit = True
        if _settings['fault-mode'] == 'eio':
            import nbdkit
            _emit('injected', **row, errno=errno.EIO, phase='before',
                  disk_sha256=_digest(handle), pending_bytes=len(handle['pending']) * SECTOR)
            nbdkit.set_error(errno.EIO)
            raise OSError(errno.EIO, 'observed actual block request rejected')
        if _settings['fault-mode'] == 'pause-before':
            _pause(handle, row, 'before')
    return row, selected


def _pause(handle, row, phase):
    _emit('paused', **row, phase=phase, disk_sha256=_digest(handle),
          pending_bytes=len(handle['pending']) * SECTOR)
    deadline = time.monotonic() + 20
    while not Path(_settings['gate']).exists():
        if time.monotonic() >= deadline:
            raise TimeoutError('host did not release or kill the observed request within20seconds')
        time.sleep(.01)
    _emit('released', **row, phase=phase)


def pwrite(handle, buffer, offset, flags):
    global _arm_pending, _armed
    _range(handle, len(buffer), offset)
    if flags:
        raise OSError(errno.EINVAL, 'this explicit test device does not advertise FUA')
    data = bytes(buffer)
    if (_armed and _settings['control-end-marker'] and
            offset == _settings['control-offset'] and data.startswith(_settings['control-end-marker'])):
        _emit('disarmed', disk_sha256=_digest(handle), requests=dict(_counts),
              pending_bytes=len(handle['pending']) * SECTOR)
        _armed = False
    row, selected = _request(handle, 'write', offset=offset, bytes=len(data),
                             payload_sha256=hashlib.sha256(data).hexdigest())
    if _settings['cache-model'] == 'writethrough':
        _write(handle['fd'], data, offset)
        os.fsync(handle['fd'])
    else:
        positions = range(offset, offset + len(data), SECTOR)
        if (len(set(handle['pending']).union(positions)) * SECTOR) > CACHE_LIMIT:
            raise RuntimeError('volatile sector cache exceeds16MiB')
        for position in positions:
            handle['pending'][position] = data[position - offset:position - offset + SECTOR]
    if (offset == _settings['control-offset'] and data.startswith(_settings['control-marker']) and
            not _armed):
        _arm_pending = True
    if row:
        _emit('write_complete', **row, payload_hex=data.hex(),
              pending_bytes=len(handle['pending']) * SECTOR)
    if selected and _settings['fault-mode'] == 'pause-after':
        _pause(handle, row, 'after')


def flush(handle, flags):
    global _armed, _arm_pending, _durable_generation
    row, selected = _request(handle, 'flush', pending_before=len(handle['pending']) * SECTOR)
    for offset, data in sorted(handle['pending'].items()):
        _write(handle['fd'], data, offset)
    os.fsync(handle['fd'])
    handle['pending'].clear()
    _durable_generation += 1
    if _arm_pending:
        destination = Path(_settings['trace']).with_name('armed.raw')
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            offset = 0
            while data := os.pread(handle['fd'], 1024 * 1024, offset):
                _write(fd, data)
                offset += len(data)
            os.fsync(fd)
        finally:
            os.close(fd)
        _armed, _arm_pending = True, False
        _emit('armed', disk_sha256=_digest(handle), snapshot=str(destination))
    if row:
        _emit('flush_complete', **row, disk_sha256=_digest(handle))
    if selected and _settings['fault-mode'] == 'pause-after':
        _pause(handle, row, 'after')

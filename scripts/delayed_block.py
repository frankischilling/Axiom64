"""Local nbdkit test backend: ordinary file I/O and controlled flush latency."""
import builtins
import json
import os
import time

API_VERSION = 2
filename = trace = ''
delay = 0


def config(key, value):
    global filename, trace, delay
    if key == 'disk':
        filename = value
    elif key == 'trace':
        trace = value
    elif key == 'delay':
        delay = int(value)
    else:
        raise ValueError(f'unknown backend parameter: {key}')


def config_complete():
    if not filename or not trace or delay not in range(41):
        raise ValueError('disk, trace, and a flush delay of 0..40 seconds are required')


def open(readonly):
    return os.open(filename, (os.O_RDONLY if readonly else os.O_RDWR) | os.O_CLOEXEC)


def close(handle):
    os.close(handle)


def get_size(handle):
    return os.fstat(handle).st_size


def can_write(handle):
    return True


def can_flush(handle):
    return True


def pread(handle, buffer, offset, flags):
    data = os.pread(handle, len(buffer), offset)
    if len(data) != len(buffer):
        raise OSError('short backend read')
    buffer[:] = data


def pwrite(handle, buffer, offset, flags):
    if os.pwrite(handle, buffer, offset) != len(buffer):
        raise OSError('short backend write')


def record(event, seconds):
    with builtins.open(trace, 'a') as output:
        output.write(json.dumps(dict(event=event, seconds=seconds, at=time.monotonic())) + '\n')


def flush(handle, flags):
    started = time.monotonic()
    record('flush_begin', delay)
    time.sleep(delay)
    os.fsync(handle)
    record('flush_end', time.monotonic() - started)

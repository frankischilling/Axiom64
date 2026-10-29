# SPDX-License-Identifier: GPL-3.0-or-later
"""Own disposable NBD startup and retain the actual failed process before reaping."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


def _read(path, limit=8192):
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(limit + 1)
        return dict(text=data[:limit].decode(errors='replace'), truncated=len(data) > limit)
    except OSError as error:
        return dict(error=type(error).__name__)


def _process_state(process):
    root = Path('/proc') / str(process.pid)
    state = dict(pid=process.pid, returncode=process.poll())
    for name in ('stat', 'status', 'wchan', 'io', 'stack'):
        state[name] = _read(root / name)
    state['maps'] = _read(root / 'maps', 65536)
    try:
        state['executable'] = str((root / 'exe').resolve(strict=True))
    except OSError as error:
        state['executable_error'] = type(error).__name__
    return state


def _file_state(path):
    try:
        value = path.stat()
        return dict(exists=True, bytes=value.st_size, mode=value.st_mode)
    except OSError as error:
        return dict(exists=False, error=type(error).__name__)


def _executable(command):
    path = shutil.which(command[0])
    if not path:
        return dict(found=False)
    try:
        with Path(path).open('rb') as stream:
            return dict(path=path, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())
    except OSError as error:
        return dict(path=path, error=type(error).__name__)


def launch_backend(command, socket, directory):
    """Keep the original five-second socket bound; diagnostics never grant a retry."""
    diagnostic = directory / 'backend-startup.json'
    if diagnostic.exists():
        raise FileExistsError(diagnostic)
    output = (directory / 'backend.log').open('xb')
    process = None
    report = dict(command=command, deadline_seconds=5, pid=None, passed=False,
                  socket=str(socket), launch_monotonic_ns=time.monotonic_ns(), failure='launch')
    try:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        began = time.monotonic_ns()
        deadline = time.monotonic() + 5
        report.update(pid=process.pid, start_monotonic_ns=began)
        while not socket.exists():
            exited = process.poll() is not None
            if exited or time.monotonic() > deadline:
                report.update(failure='process-exit' if exited else 'deadline',
                              observation_elapsed_ns=time.monotonic_ns() - began,
                              process_before_termination=_process_state(process),
                              host_cpu_pressure=_read('/proc/pressure/cpu'),
                              host_memory_pressure=_read('/proc/pressure/memory'))
                raise RuntimeError('bounded disposable NBD backend did not start')
            time.sleep(.01)
        report.update(passed=True, failure=None, observation_elapsed_ns=time.monotonic_ns() - began)
        report.update(executable=_executable(command), socket_state=_file_state(socket),
                      configuration_trace=_file_state(directory / 'block.jsonl'))
        diagnostic.write_text(json.dumps(report, indent=2) + '\n')
    except BaseException as error:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
        output.close()
        report.update(passed=False, exception_type=type(error).__name__,
                      returncode=process.returncode if process is not None else None,
                      executable=_executable(command), socket_state=_file_state(socket),
                      configuration_trace=_file_state(directory / 'block.jsonl'))
        try:
            diagnostic.write_text(json.dumps(report, indent=2) + '\n')
        except OSError as diagnostic_error:
            error.add_note('Startup diagnostic retention failed: ' + type(diagnostic_error).__name__)
        raise
    return process, output

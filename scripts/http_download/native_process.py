# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain native output and retire an owned PID namespace before returning."""
import os
from pathlib import Path
import signal
import subprocess
import time

from http_download.audit import fingerprint


def identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
        return fields[0],fields[19]
    except FileNotFoundError:
        return None


def alive(pid, expected):
    current = identity(pid)
    return expected is not None and current is not None and current[1] == expected[1] and current[0] != 'Z'


def run(command, stdout, stderr, timeout):
    # The namespace init retires even detached descendants when it exits. The
    # controller and init share a process group; inner clients may own others.
    wrapper = ['unshare','--mount','--propagation','private','--pid','--fork',
               '--kill-child','--mount-proc','--',*command]
    started = time.monotonic_ns()
    process, timed_out, namespace_children = None, False, {}
    with stdout.open('wb') as output:
        errors = stderr.open('wb') if stderr is not None else None
        try:
            process = subprocess.Popen(wrapper,stdin=subprocess.DEVNULL,stdout=output,
                stderr=errors if errors is not None else subprocess.STDOUT,start_new_session=True,umask=0o077)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                children = Path(f'/proc/{process.pid}/task/{process.pid}/children')
                for pid in children.read_text().split() if children.exists() else ():
                    namespace_children[int(pid)] = identity(int(pid))
        finally:
            if process is not None:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL)
                process.wait()
                end = time.monotonic()+5
                while any(alive(pid,value) for pid,value in namespace_children.items()):
                    if time.monotonic() >= end:
                        raise RuntimeError('native PID namespace did not retire before evidence handoff')
                    time.sleep(.01)
            if errors is not None:
                errors.close()
    return dict(command=wrapper,returncode=process.returncode,timed_out=timed_out,
                elapsed_ns=time.monotonic_ns()-started,stdout=fingerprint(stdout),
                stderr=fingerprint(stderr) if stderr is not None else None,
                owned_namespace_retired=True)

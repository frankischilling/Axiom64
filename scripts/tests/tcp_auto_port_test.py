# SPDX-License-Identifier: GPL-3.0-or-later
"""Prove failed automatic bind ownership despite unrelated native TIME_WAIT ports."""
import errno
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from build_musl import loader


def require(value, message):
    if not value:
        raise ValueError(message)


def listener():
    value = socket.socket()
    value.bind(('127.0.0.1', 0))
    value.listen()
    return value


def clamp(value, port):
    # Linux IP_LOCAL_PORT_RANGE: constrain automatic selection without bind().
    value.setsockopt(socket.IPPROTO_IP, 51, struct.pack('I', port | port << 16))


def refused(port, target):
    with socket.socket() as value, socket.socket() as competitor:
        clamp(value, port)
        value.setblocking(False)
        require(value.connect_ex(target) == errno.EINPROGRESS, 'actual pending refused connection')
        poller = select.poll()
        poller.register(value, select.POLLOUT)
        require(poller.poll(2000), 'finite actual refusal readiness')
        require(value.getsockname()[1] == port and value.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) ==
                errno.ECONNREFUSED, 'the unbound connection owns the clamped automatically selected port')
        failure = 0
        try:
            competitor.bind(value.getsockname())
        except OSError as error:
            failure = error.errno
        return failure


def namespace():
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    reservation, server, unavailable = listener(), listener(), listener()
    old_port, target = reservation.getsockname()[1], unavailable.getsockname()
    reservation.close()
    first = socket.socket()
    clamp(first, old_port)
    first.connect(server.getsockname())
    accepted, _ = server.accept()
    first.close()
    require(accepted.recv(1) == b'', 'actual orderly active close reaches the independent peer')
    accepted.close()
    server.close()
    time.sleep(.1)
    states = subprocess.check_output(['ss', '-Htn', 'state', 'time-wait'], text=True)
    require(f':{old_port} ' in states, 'the preceding actual TCP connection remains in TIME_WAIT')
    fresh = listener()
    unused_port = fresh.getsockname()[1]
    fresh.close()
    unavailable.close()
    contaminated, unused = refused(old_port, target), refused(unused_port, target)
    require(contaminated == errno.EADDRINUSE and unused == 0,
            'unrelated TIME_WAIT masks the failed bind release; an unused port proves it')
    rows, logs = [], []
    for profile in ('native', 'static', 'dynamic'):
        command = [str(ROOT / 'build' / ('tcp-' + profile)), '--connect-port-check']
        if profile == 'dynamic':
            command.insert(0, str(loader('build')))
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=15)
        logs.append('PROFILE ' + profile + '\n' + result.stdout)
        (ROOT / 'build/tcp-auto-port.log').write_text('\n'.join(logs))
        require(result.returncode == 0 and 'TCP_AUTOMATIC_PORT_CHECK_PASS cases=4' in result.stdout and
                'TCP_CONNECT_FAILURES_PASS cases=4' in result.stdout and
                result.stdout.count('TCP_AUTOMATIC_PORT_READY') == 2,
                'all original automatic/explicit ownership and same-description retry assertions pass: ' +
                profile + ': ' + result.stdout[-500:])
        rows.append(dict(profile=profile, returncode=result.returncode, passed=True))
    report = dict(passed=True, namespace=os.readlink('/proc/self/ns/net'),
                  kernel=subprocess.check_output(['uname', '-r'], text=True).strip(),
                  actual_time_wait=states, contaminated_port=old_port, contaminated_bind_errno=contaminated,
                  unused_port=unused_port, unused_bind_errno=unused, comparisons=rows)
    (ROOT / 'build/tcp-auto-port-results.json').write_text(json.dumps(report, indent=2) + '\n')
    (ROOT / 'build/tcp-auto-port.log').write_text('\n'.join(logs))
    print('TCP_AUTO_PORT_REGRESSION_PASS contaminated_bind=98 unused_bind=0 profiles=3 cases=12')


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--namespace':
        namespace()
        return
    require(os.geteuid() == 0, 'native regression requires a private network namespace')
    before = os.readlink('/proc/self/ns/net')
    subprocess.run(['unshare', '--net', sys.executable, str(Path(__file__).resolve()), '--namespace'], check=True)
    report = json.loads((ROOT / 'build/tcp-auto-port-results.json').read_text())
    require(report['namespace'] != before and os.readlink('/proc/self/ns/net') == before,
            'the original network namespace remains unchanged')


if __name__ == '__main__':
    main()

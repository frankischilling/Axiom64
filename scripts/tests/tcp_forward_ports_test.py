# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep real forwarding ports exclusive until the actual QEMU launch handoff."""
import errno
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_native_wire import NativePeer


def require(value, message):
    if not value:
        raise AssertionError(message)


def blocked(port):
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', port))
        except OSError as error:
            require(error.errno == errno.EADDRINUSE, 'the retained listener excludes competing binds')
            return True
    return False


def qemu(peers):
    command = ['qemu-system-x86_64', '-machine', 'pc', '-nodefaults', '-S',
               '-display', 'none', '-monitor', 'stdio', '-serial', 'none']
    for peer in peers:
        command += ['-netdev', f'user,id=peer{peer.lane},hostfwd=tcp:127.0.0.1:'
                    f'{peer.forward_port}-:41000']
    return subprocess.run(command, input=b'info usernet\nquit\n', stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=5)


def constructor_failure():
    original = resource.getrlimit(resource.RLIMIT_NOFILE)
    occupied = [int(name) for name in os.listdir('/proc/self/fd')
                if os.path.exists('/proc/self/fd/' + name)]
    first_free = next(number for number in range(original[1]) if number not in occupied)
    limit = next(number for number in range(first_free + 1, original[1]) if number not in occupied)
    require(limit <= original[1], 'the owned process can reserve one remaining descriptor')
    failure = None
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (limit, original[1]))
        try:
            NativePeer(0)
        except OSError as error:
            require(error.errno == errno.EMFILE, 'the second actual socket allocation hits the descriptor limit')
            failure = error
        require(failure is not None, 'the actual constructor failed before creating its forwarding socket')
        # Keep the exception/constructor frame alive so garbage collection
        # cannot substitute for explicit partial-construction cleanup.
        with socket.socket() as probe:
            require(probe.fileno() >= 0, 'the failed constructor released its first actual socket')
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, original)


def main():
    peers = []
    (ROOT / 'build').mkdir(exist_ok=True)
    try:
        for lane in range(2):
            peers.append(NativePeer(lane))
        addresses = [port for peer in peers for port in (peer.port, peer.forward_port)]
        require(len(set(addresses)) == 4, 'both peer listeners and forwarding ports have distinct owners')
        for peer in peers:
            require(blocked(peer.forward_port),
                    'the forwarding reservation survives peer creation and fixture construction')
        held = qemu(peers)
        require(held.returncode == 1 and b'Could not set up host forwarding rule' in held.stdout,
                'the actual QEMU startup cannot steal a still-reserved forwarding port')
        for peer in peers:
            peer.release_forwarding()
        launched = qemu(peers)
        require(launched.returncode == 0 and b'TCP[HOST_FORWARD]' in launched.stdout,
                'actual QEMU installs forwarding rules after the explicit handoff')
        for peer in peers:
            require(str(peer.forward_port).encode() in launched.stdout,
                    'QEMU reports the actual selected forwarding port')
        for peer in peers:
            peer.close()
        released = NativePeer(0)
        peers.append(released)
        port = released.forward_port
        require(blocked(port), 'the abandoned fixture owns its forwarding listener')
        released.close()
        require(not blocked(port), 'fixture cleanup releases an unused forwarding listener')
        constructor_failure()
        result = dict(passed=True, observations=6, addresses=addresses,
                      held_qemu_returncode=held.returncode, launched_qemu_returncode=launched.returncode)
        (ROOT / 'build/tcp-forward-ports.log').write_bytes(held.stdout + launched.stdout)
        (ROOT / 'build/tcp-forward-ports-results.json').write_text(json.dumps(result, indent=2) + '\n')
        print('TCP_FORWARD_PORTS_PASS observations=6 actual_qemu_handoffs=2')
    finally:
        for peer in peers:
            peer.close()


if __name__ == '__main__':
    main()

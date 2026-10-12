# SPDX-License-Identifier: GPL-3.0-or-later
"""Reproduce shared ephemeral ownership and verify exclusive fixture reservations."""
import argparse
import errno
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys

IP_LOCAL_PORT_RANGE = 51
IP_BIND_ADDRESS_NO_PORT = 24


def abort(client):
    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    client.close()


def observe(explicit):
    servers, peers, clients, ports = [], [], [], []
    try:
        for index in range(3):
            server = socket.socket()
            assert server.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
            server.bind(('127.0.0.1', 12300 + index))
            server.listen(1)
            servers.append(server)
            client = socket.socket()
            assert client.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
            if explicit:
                client.bind(('127.0.0.2', 46600 + index))
            else:
                client.setsockopt(socket.IPPROTO_IP, IP_LOCAL_PORT_RANGE,
                                  struct.pack('I', (46401 << 16) | 46400))
                client.setsockopt(socket.IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1)
                client.bind(('127.0.0.2', 0))
            client.connect(server.getsockname())
            peer, _ = server.accept()
            clients.append(client)
            peers.append(peer)
            ports.append(client.getsockname()[1])
        if explicit:
            assert ports == [46600, 46601, 46602]
            for client in clients:
                local = client.getsockname()
                abort(client)
                with socket.socket() as probe:
                    probe.bind(local)
                    probe.listen(1)
            return dict(explicit=True, ports=ports, immediate_rebinds=3, passed=True)
        assert set(ports) <= {46400, 46401}
        pair, = [indexes for port in set(ports)
                 if len(indexes := [index for index, value in enumerate(ports) if value == port]) > 1]
        local = clients[pair[0]].getsockname()
        abort(clients[pair[0]])
        with socket.socket() as probe:
            try:
                probe.bind(local)
            except OSError as error:
                assert error.errno == errno.EADDRINUSE
            else:
                raise AssertionError('another live connection still owns the shared local port')
        for index in pair[1:]:
            abort(clients[index])
        with socket.socket() as probe:
            probe.bind(local)
            probe.listen(1)
        return dict(explicit=False, ports=ports, shared_port=local[1], held_live_error=errno.EADDRINUSE,
                    after_last_owner_immediate_rebind=True, passed=True)
    finally:
        for descriptor in [*clients, *peers, *servers]:
            descriptor.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace', action='store_true')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[2] /
                        'build/tcp-lifetime-port-ownership.json')
    args = parser.parse_args()
    if not args.namespace:
        if os.geteuid() != 0:
            raise RuntimeError('the disposable native network namespace requires root')
        original = os.readlink('/proc/self/ns/net')
        subprocess.run(['unshare', '--net', sys.executable, __file__, '--namespace', '--output',
                        str(args.output)], check=True)
        assert os.readlink('/proc/self/ns/net') == original
        return
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    rows = [observe(False), observe(True)]
    result = dict(cases=rows, socket_reuse_enabled=False, host_configuration_changed=False, passed=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('TCP_LIFETIME_PORT_OWNERSHIP_PASS ' + json.dumps(result), flush=True)


if __name__ == '__main__':
    main()

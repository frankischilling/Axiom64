# SPDX-License-Identifier: GPL-3.0-or-later
"""Own normal-session DNS, native endpoints and namespace-only resolver settings."""
import hashlib
from collections import Counter
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading

from dns_peer import question, response
from http_download.peer import Peer
from http_download.wire import PAYLOAD_BYTES, PAYLOAD_SHA256
from random_crypto.peer import certificates
from tcp_fault_capture import require


def dns_reply(query):
    if len(query) < 4 or query[-4:] not in (b'\0\1\0\1', b'\0\x1c\0\1'):
        raise ValueError('normal DNS fixture requires one IN A or AAAA question')
    ipv4 = query[-4:] == b'\0\1\0\1'
    normalized = query[:-4]+b'\0\1\0\1'
    name = question(normalized)
    positive = {f'{prefix}{lane}.axiom64.test': lane for prefix in ('lane', 'wrong') for lane in (0, 1)}
    if name in positive:
        lane = positive[name]
        answer = response(normalized, ((10, 23, lane+1, 1),) if ipv4 else ())
    elif name == 'missing.axiom64.test':
        answer = response(normalized, rcode=3)
    else:
        raise ValueError('unexpected normal-session DNS query: '+name)
    # Return the actual query type unchanged. A valid AAAA lookup receives
    # NODATA rather than being dropped by the IPv4-only address fixture.
    return name, answer[:len(query)-4]+query[-4:]+answer[len(query):]


def certificate_fixture(directory, openssl):
    certificates(directory, openssl)
    extensions = directory / 'normal-server.cnf'
    extensions.write_text('''basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:axiom64.test,DNS:lane0.axiom64.test,DNS:lane1.axiom64.test
''')
    environment = dict(os.environ, OPENSSL_CONF='/dev/null')
    commands = [[str(openssl), 'x509', '-req', '-in', 'peer.csr', '-CA', 'ca.pem',
                 '-CAkey', 'ca.key', '-set_serial', '42', '-days', '2', '-sha256',
                 '-extfile', extensions.name, '-out', 'valid.pem']]
    commands += [[str(openssl), 'verify', '-CAfile', 'ca.pem', '-verify_hostname', name, 'valid.pem']
                 for name in ('axiom64.test', 'lane0.axiom64.test', 'lane1.axiom64.test')]
    with (directory / 'normal-generation.log').open('wb') as log:
        for command in commands:
            subprocess.run(command, cwd=directory, env=environment, check=True,
                           stdout=log, stderr=subprocess.STDOUT, timeout=30)
    (directory / 'normal-commands.json').write_text(json.dumps(commands, indent=2)+'\n')


class Network:
    def __init__(self, directory, certificates, timeout):
        self.directory = directory
        self.original_resolver = Path('/etc/resolv.conf').read_bytes()
        self.queries, self.errors, self.peers, self.refused = [], [], {}, {}
        self.refused_ports = {}
        self.stop = threading.Event()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.thread = None
        try:
            self.server.bind(('127.0.0.55', 53))
            self.server.settimeout(.2)
            for lane in (0, 1):
                self.peers[lane] = {}
                for name in ('http', 'untrusted', 'fallback'):
                    self.peers[lane][name] = Peer(name, certificates, timeout)
                # Exercise the internal wget fallback with its actual TLS 1.2
                # and SHA-256 cipher support, without changing any client option.
                fallback = self.peers[lane]['fallback']
                fallback.context.minimum_version = fallback.context.maximum_version = ssl.TLSVersion.TLSv1_2
                fallback.context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
                reservation = socket.socket()
                reservation.bind(('127.0.0.1', 0))
                self.refused[lane] = reservation
                self.refused_ports[lane] = reservation.getsockname()[1]
            (directory / 'resolver.conf').write_text('nameserver 127.0.0.55\noptions timeout:1 attempts:1\n')
            (directory / 'resolver-child.py').write_text('''import os,subprocess,sys
subprocess.run(['mount','--bind',sys.argv[1],'/etc/resolv.conf'],check=True)
os.execvp(sys.argv[2],sys.argv[2:])
''')
            self.thread = threading.Thread(target=self.answer, name='download-normal-dns')
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def answer(self):
        while not self.stop.is_set():
            try:
                query, sender = self.server.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                name, answer = dns_reply(query)
                self.queries.append(dict(name=name, query=query.hex(), answer=answer.hex()))
                self.server.sendto(answer, sender)
            except BaseException as error:
                self.errors.append(dict(query=query.hex(), sender=list(sender), error=repr(error)))

    def command(self, command):
        return ['unshare', '--mount', '--propagation', 'private', '--', sys.executable,
                str(self.directory / 'resolver-child.py'), str(self.directory / 'resolver.conf'), *command]

    def refused_port(self, lane):
        return self.refused_ports[lane]

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
            if self.thread.is_alive():
                raise RuntimeError('normal DNS observer did not stop')
        self.server.close()
        for group in self.peers.values():
            for peer in group.values():
                if not peer.result['closed']:
                    peer.close()
        for reservation in self.refused.values():
            reservation.close()
        unchanged = Path('/etc/resolv.conf').read_bytes() == self.original_resolver
        report = dict(queries=self.queries, errors=self.errors,
                      peers={lane: {name: peer.result for name,peer in group.items()}
                             for lane,group in self.peers.items()}, refused_ports=self.refused_ports,
                      host_resolver_unchanged=unchanged,
                      host_resolver_sha256=hashlib.sha256(self.original_resolver).hexdigest())
        (self.directory / 'network.json').write_text(json.dumps(report, indent=2)+'\n')
        if not unchanged:
            raise RuntimeError('normal network fixture changed the parent resolver')


def verify_peers(peers, phases, profiles):
    """Require each actual application request and certificate rejection."""
    count = len(phases)
    fresh = sum(row['phase'] in ('ram', 'create') for row in phases)
    clients = len(profiles)
    require(set(peers) == {'0', '1'}, 'both normal adapters have native observers')
    for group in peers.values():
        require(set(group) == {'http', 'untrusted', 'fallback'}, 'all normal HTTP/TLS endpoints')
        for name, peer in group.items():
            require(peer['closed'] and not peer['errors'] and peer['name'] == name and
                    (peer['payload_bytes'], peer['payload_sha256']) == (PAYLOAD_BYTES, PAYLOAD_SHA256),
                    'complete normal native peer with the independent payload contract')
            expected = Counter({'/fixed': (clients+1)*count, '/small': clients*count}) if name == 'http' else Counter(
                {'/fixed': fresh if name == 'fallback' else (clients+1)*count})
            # A reboot-only diagnostic can have no internal-fallback request.
            expected = +expected
            require(Counter(row['target'] for row in peer['requests']) == expected,
                    'every required normal native application exchange: '+name)
            for row in peer['requests']:
                require(row['sent'], 'normal native endpoint sent the complete response')
                if row['target'] == '/fixed':
                    require((row['body_bytes'], row['body_sha256']) == (PAYLOAD_BYTES, PAYLOAD_SHA256),
                            'normal native endpoint sent every actual binary byte')
                require(row['tls_version'] == (None if name == 'http' else
                        'TLSv1.2' if name == 'fallback' else 'TLSv1.3'), 'actual normal TLS version')
            rejects = len(peer['rejected_handshakes'])+len(peer['rejected_after_handshake'])
            require(rejects == (3*(clients+1)*fresh+count if name == 'untrusted' else 0),
                    'actual public/missing/damaged-store and wrong-DNS-name certificate rejections')
            require(all(row['application_bytes'] == 0 for row in peer['rejected_after_handshake']),
                    'normal certificate rejection contains no partial HTTP request')
    return dict(passed=True, phases=count, fresh_phases=fresh, curl_profiles=list(profiles))

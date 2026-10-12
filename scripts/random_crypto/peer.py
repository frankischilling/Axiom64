# SPDX-License-Identifier: GPL-3.0-or-later
"""An independent native TLS endpoint with explicit certificate failure controls."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time

PAYLOAD = b'Axiom64 authenticated encrypted client\n'


def certificates(directory, openssl):
    directory.mkdir(mode=0o700)
    environment = dict(os.environ, OPENSSL_CONF='/dev/null')
    commands = []

    def run(arguments):
        command = [str(openssl), *arguments]
        commands.append(command)
        with (directory / 'generation.log').open('ab') as log:
            subprocess.run(command, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                           stdout=log, stderr=subprocess.STDOUT, check=True, timeout=30)

    for name in ('ca', 'untrusted'):
        run(['req', '-new', '-x509', '-newkey', 'rsa:2048', '-noenc', '-sha256', '-days', '3',
             '-subj', '/CN=Axiom64 test ' + name, '-addext', 'basicConstraints=critical,CA:TRUE',
             '-keyout', name + '.key', '-out', name + '.pem'])
    run(['req', '-new', '-newkey', 'rsa:2048', '-noenc', '-sha256', '-subj', '/CN=axiom64.test',
         '-keyout', 'peer.key', '-out', 'peer.csr'])
    (directory / 'index').write_text('')
    (directory / 'index.attr').write_text('unique_subject = no\n')
    (directory / 'serial').write_text('01\n')
    (directory / 'issued').mkdir()
    (directory / 'ca.cnf').write_text('''[ca]
default_ca = local
[local]
database = index
serial = serial
new_certs_dir = issued
certificate = ca.pem
private_key = ca.key
default_md = sha256
default_days = 2
policy = names
x509_extensions = server
[names]
commonName = supplied
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:axiom64.test
''')
    now = datetime.now(timezone.utc)
    for name, start, end in (('valid', now-timedelta(hours=1), now+timedelta(days=2)),
                             ('expired', now-timedelta(days=3), now-timedelta(days=2)),
                             ('future', now+timedelta(days=1), now+timedelta(days=2))):
        run(['ca', '-batch', '-notext', '-config', 'ca.cnf', '-in', 'peer.csr',
             '-out', name + '.pem', '-startdate', start.strftime('%Y%m%d%H%M%SZ'),
             '-enddate', end.strftime('%Y%m%d%H%M%SZ')])
    for path in directory.glob('*.key'):
        path.chmod(0o600)
    (directory / 'commands.json').write_text(json.dumps(commands, indent=2)+'\n')


class Peer:
    def __init__(self, name, certificates, timeout):
        self.name, self.timeout = name, timeout
        self.expected = name in ('tls12', 'tls13')
        self.protocol = 'TLSv1.2' if name == 'tls12' else 'TLSv1.3'
        self.response = ('AXIOM64_TLS_PEER_PASS ' + name + '\n').encode()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        version = ssl.TLSVersion.TLSv1_2 if name == 'tls12' else ssl.TLSVersion.TLSv1_3
        self.context.minimum_version = self.context.maximum_version = version
        self.context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
        certificate = name if name in ('expired', 'future') else 'valid'
        self.context.load_cert_chain(certificates / (certificate + '.pem'), certificates / 'peer.key')
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(.25)
        self.port = self.listener.getsockname()[1]
        self.result = dict(name=name, port=self.port, expected_success=self.expected, passed=False)
        self.connection = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.exchange, name='tls-peer-' + name)
        self.thread.start()

    def exchange(self):
        started = time.monotonic_ns()
        try:
            deadline = time.monotonic()+self.timeout
            while not self.stop.is_set() and time.monotonic() < deadline:
                try:
                    self.connection, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            if self.connection is None:
                raise RuntimeError('TLS peer received no connection before its deadline')
            self.connection.settimeout(30)
            try:
                encrypted = self.context.wrap_socket(self.connection, server_side=True)
                self.connection = encrypted
            except ssl.SSLError as error:
                if self.expected:
                    raise
                self.result.update(handshake_rejected=True, tls_error=str(error), passed=True)
                return
            with encrypted:
                if not self.expected:
                    raise RuntimeError('invalid certificate/hostname completed its handshake')
                message = bytearray()
                while b'\n' not in message and len(message) < 4096:
                    block = encrypted.recv(4096)
                    if not block:
                        break
                    message.extend(block)
                if bytes(message) != PAYLOAD or encrypted.version() != self.protocol:
                    raise RuntimeError('native peer received different data or protocol')
                self.result.update(protocol=encrypted.version(), cipher=encrypted.cipher(),
                                   message_sha256=hashlib.sha256(message).hexdigest(),
                                   response_sha256=hashlib.sha256(self.response).hexdigest())
                encrypted.sendall(self.response)
                encrypted.unwrap().close()
                self.result.update(close_notify=True, passed=True)
        except BaseException as error:
            self.result.update(error=repr(error), passed=False)
        finally:
            self.result['elapsed_ns'] = time.monotonic_ns()-started
            self.listener.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        if self.thread.is_alive() and self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            self.result.update(error='native TLS peer did not stop', passed=False)

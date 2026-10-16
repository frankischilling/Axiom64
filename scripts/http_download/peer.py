# SPDX-License-Identifier: GPL-3.0-or-later
"""Serve controlled HTTP bytes with actual native sockets and TLS handshakes."""
import hashlib
import socket
import ssl
import threading
import time

PAYLOAD = hashlib.shake_256(b'Axiom64 HTTP binary fixture version 1').digest(1024 * 1024 + 17)
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()
REJECTED_CERTIFICATES = ('hostname', 'untrusted', 'expired', 'future')


class Peer:
    def __init__(self, name, certificates, timeout):
        self.name = name
        self.timeout = timeout
        self.context = None
        if name != 'http':
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            version = ssl.TLSVersion.TLSv1_2 if name == 'tls12' else ssl.TLSVersion.TLSv1_3
            self.context.minimum_version = self.context.maximum_version = version
            self.context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384')
            certificate = name if name in ('expired', 'future') else 'valid'
            self.context.load_cert_chain(certificates / (certificate + '.pem'), certificates / 'peer.key')
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.connection_lock = threading.Lock()
        self.connection = None
        self.result = dict(name=name, port=self.port, requests=[], rejected_handshakes=[],
                           rejected_after_handshake=[],
                           payload_bytes=len(PAYLOAD), payload_sha256=PAYLOAD_SHA256,
                           errors=[], closed=False)
        self.thread = threading.Thread(target=self.exchange, name='http-peer-' + name)
        self.thread.start()

    def exchange(self):
        end = time.monotonic() + self.timeout
        while not self.stop.is_set() and time.monotonic() < end:
            try:
                connection, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError as error:
                if not self.stop.is_set():
                    self.result['errors'].append(repr(error))
                break
            started = time.monotonic_ns()
            try:
                connection.settimeout(min(10, self.timeout))
                # Publish the live TLS socket before its blocking handshake.
                # Closing the detached original socket cannot interrupt it.
                with self.connection_lock:
                    if self.stop.is_set():
                        continue
                    if self.context:
                        connection = self.context.wrap_socket(connection, server_side=True,
                                                              do_handshake_on_connect=False)
                    self.connection = connection
                if self.context:
                    try:
                        connection.do_handshake()
                    except (ssl.SSLError, ConnectionResetError) as error:
                        self.result['rejected_handshakes'].append(dict(error=repr(error),
                            elapsed_ns=time.monotonic_ns()-started))
                        continue
                raw = bytearray()
                denied = False
                while b'\r\n\r\n' not in raw:
                    try:
                        chunk = connection.recv(4096)
                    except (ssl.SSLError, ConnectionResetError) as error:
                        if raw or self.name not in REJECTED_CERTIFICATES:
                            raise
                        self.result['rejected_after_handshake'].append(dict(error=repr(error),
                            elapsed_ns=time.monotonic_ns()-started, application_bytes=0))
                        denied = True
                        break
                    if not chunk and not raw and self.name in REJECTED_CERTIFICATES:
                        self.result['rejected_after_handshake'].append(dict(reason='closed before HTTP',
                            elapsed_ns=time.monotonic_ns()-started, application_bytes=0))
                        denied = True
                        break
                    if not chunk or len(raw) + len(chunk) > 16384:
                        raise RuntimeError('missing or oversized actual HTTP request')
                    raw.extend(chunk)
                if denied:
                    continue
                header, tail = bytes(raw).split(b'\r\n\r\n', 1)
                lines = header.decode('iso-8859-1').split('\r\n')
                method, target, version = lines[0].split(' ')
                if method != 'GET' or version not in ('HTTP/1.0', 'HTTP/1.1') or tail:
                    raise RuntimeError('unexpected request method, version or body')
                fields = {}
                for line in lines[1:]:
                    name, value = line.split(':', 1)
                    key = name.lower()
                    if key in fields:
                        raise RuntimeError('repeated fixture request field: ' + key)
                    fields[key] = value.strip()
                row = dict(request=bytes(raw).hex(), method=method, target=target, version=version,
                    headers=fields, remote_address=address[0], started_ns=started,
                    tls_version=connection.version() if self.context else None,
                    cipher=connection.cipher() if self.context else None)
                self.result['requests'].append(row)
                status = '200 OK'
                headers = []
                body = PAYLOAD
                if target == '/redirect':
                    status, body = '302 Found', b''
                    headers.append(('Location', '/fixed'))
                elif target == '/missing':
                    status, body = '404 Not Found', b'fixture does not exist\n'
                elif target == '/small':
                    body = b'Axiom64 output permission fixture\n'
                elif target == '/stall':
                    self.stop.wait(4)
                    row.update(stalled=True, elapsed_ns=time.monotonic_ns()-started)
                    continue
                elif target == '/range':
                    value = fields.get('range', '')
                    if not value.startswith('bytes=') or not value.endswith('-'):
                        raise RuntimeError('resume request lacks its actual byte range')
                    start = int(value[6:-1])
                    if not 0 < start < len(PAYLOAD):
                        raise RuntimeError('resume range is outside the fixture')
                    status, body = '206 Partial Content', PAYLOAD[start:]
                    headers.append(('Content-Range', f'bytes {start}-{len(PAYLOAD)-1}/{len(PAYLOAD)}'))
                    row['range_start'] = start
                elif target not in ('/fixed', '/chunked', '/truncated'):
                    raise RuntimeError('unexpected HTTP fixture path: ' + target)
                if target == '/chunked':
                    headers.append(('Transfer-Encoding', 'chunked'))
                    chunks = []
                    for offset in range(0, len(body), 8191):
                        chunk = body[offset:offset+8191]
                        chunks.append(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                    encoded = b''.join(chunks) + b'0\r\nX-Axiom64-Trailer: complete\r\n\r\n'
                else:
                    headers.append(('Content-Length', str(len(body))))
                    encoded = body[:len(body)//2] if target == '/truncated' else body
                headers += [('Content-Type', 'application/octet-stream'), ('Connection', 'close')]
                response = ('HTTP/1.1 ' + status + '\r\n' +
                    ''.join(name+': '+value+'\r\n' for name, value in headers) + '\r\n').encode()
                connection.sendall(response + encoded)
                row.update(status=status, response_header=response.hex(),
                    body_bytes=len(encoded), body_sha256=hashlib.sha256(encoded).hexdigest(),
                    elapsed_ns=time.monotonic_ns()-started, sent=True)
            except BaseException as error:
                if not self.stop.is_set():
                    self.result['errors'].append(repr(error))
            finally:
                with self.connection_lock:
                    self.connection = None
                connection.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        with self.connection_lock:
            connection = self.connection
            if connection is not None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise RuntimeError('HTTP fixture peer did not stop')
        self.result['closed'] = True

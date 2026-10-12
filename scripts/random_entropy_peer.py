#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Serve firmware entropy, then withhold a real kernel virtio RNG request."""
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time


class EntropyPeer:
    def __init__(self, serial, evidence):
        self.serial = Path(serial)
        self.evidence = Path(evidence)
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom64-entropy-peer-')
        self.path = Path(self.temporary.name) / 'entropy.sock'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.listener.listen(1)
        self.listener.settimeout(.25)
        self.stop = threading.Event()
        self.records = []
        self.failure = None
        self.withheld_at = None
        self.thread = threading.Thread(target=self.serve, name='entropy-peer')
        self.thread.start()

    def qemu_arguments(self):
        return ['-chardev', f'socket,id=entropy-socket,path={self.path}',
                '-object', 'rng-egd,id=entropy,chardev=entropy-socket']

    def save(self, row):
        self.records.append(row)
        self.evidence.write_text(json.dumps(self.records, indent=2) + '\n')

    def serve(self):
        try:
            connection = None
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            if connection is None:
                return
            with connection:
                connection.settimeout(.25)
                pending = bytearray()
                while not self.stop.is_set():
                    try:
                        data = connection.recv(256)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    pending.extend(data)
                    while len(pending) >= 2:
                        operation, size = pending[:2]
                        del pending[:2]
                        if operation != 2 or size == 0:
                            raise RuntimeError('unexpected QEMU EGD request')
                        serial = self.serial.read_bytes() if self.serial.exists() else b''
                        kernel = b'RANDOM_VIRTIO_SOURCE transport=' in serial
                        now = time.monotonic_ns()
                        row = dict(event='request', monotonic_ns=now, operation=operation,
                                   requested=size, phase='kernel' if kernel else 'firmware',
                                   serial_prefix_bytes=len(serial),
                                   serial_prefix_sha256=hashlib.sha256(serial).hexdigest(),
                                   delivered=0 if kernel else size)
                        if kernel:
                            if self.withheld_at is None:
                                self.withheld_at = now
                        else:
                            connection.sendall(os.urandom(size))
                        self.save(row)
                if pending and not self.stop.is_set():
                    raise RuntimeError('truncated QEMU EGD request')
        except Exception as error:
            self.failure = str(error)
            self.save(dict(event='failure', error=self.failure, monotonic_ns=time.monotonic_ns()))

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError('entropy peer did not stop')
        now = time.monotonic_ns()
        self.save(dict(event='closed', monotonic_ns=now,
                       withheld_ns=now-self.withheld_at if self.withheld_at else None))
        self.temporary.cleanup()
        if self.failure:
            raise RuntimeError('entropy peer failed: ' + self.failure)

    def validate(self, serial):
        data = Path(serial).read_bytes()
        requests = [row for row in self.records if row['event'] == 'request']
        for row in requests:
            prefix = data[:row['serial_prefix_bytes']]
            if hashlib.sha256(prefix).hexdigest() != row['serial_prefix_sha256']:
                raise RuntimeError('entropy request serial prefix differs')
            if (b'RANDOM_VIRTIO_SOURCE transport=' in prefix) != (row['phase'] == 'kernel'):
                raise RuntimeError('entropy request phase differs')
        kernel = [row for row in requests if row['phase'] == 'kernel']
        if not kernel or kernel[0]['requested'] != 32 or any(row['delivered'] for row in kernel):
            raise RuntimeError('kernel entropy was not withheld at the real 32-byte request')
        if not self.records[-1]['withheld_ns'] or self.records[-1]['withheld_ns'] < 2_000_000_000:
            raise RuntimeError('kernel entropy withholding did not cover its deadline')
        return dict(requests=len(requests), firmware_requests=len(requests)-len(kernel),
                    kernel_requests=len(kernel), withheld_ns=self.records[-1]['withheld_ns'])

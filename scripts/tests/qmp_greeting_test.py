# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay the captured early notification through the real Unix QMP client."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from random_snapshot_test import QMP

FIXTURES = Path(__file__).parent / 'fixtures'
GREETING = {'QMP': {'version': {'qemu': {'major': 8, 'minor': 2, 'micro': 2},
                             'package': 'test control'}, 'capabilities': []}}


class Alive:
    def poll(self):
        return None


@contextmanager
def peer(messages, *, close_after_messages=False, delay=0, fragment=0, cap_event=None):
    with tempfile.TemporaryDirectory(prefix='axiom64-qmp-greeting-', dir='/tmp') as temporary:
        root = Path(temporary)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(root / 'qmp.sock'))
        listener.listen(1)
        listener.settimeout(2)
        commands, errors = [], []

        def server():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(2)
                    for value in messages:
                        packet = json.dumps(value).encode() + b'\r\n'
                        width = fragment or len(packet)
                        for start in range(0, len(packet), width):
                            connection.sendall(packet[start:start + width])
                            if delay:
                                time.sleep(delay)
                    if close_after_messages:
                        return
                    with connection.makefile('rb') as stream:
                        for expected in ('qmp_capabilities', 'query-status'):
                            raw = stream.readline()
                            if not raw:
                                return
                            command = json.loads(raw)
                            commands.append(command)
                            if command['execute'] != expected:
                                raise AssertionError(command)
                            reply = {'return': {} if expected == 'qmp_capabilities' else {'running': True},
                                     'id': command['id']}
                            if cap_event and expected == 'qmp_capabilities':
                                connection.sendall(json.dumps(cap_event).encode() + b'\n')
                            connection.sendall(json.dumps(reply).encode() + b'\n')
            except (BrokenPipeError, ConnectionResetError):
                pass
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=server)
        worker.start()
        try:
            yield root, commands
        finally:
            listener.close()
            worker.join(3)
            if worker.is_alive():
                raise AssertionError('QMP test peer did not terminate')
            if errors:
                raise errors[0]


class QMPGreeting(unittest.TestCase):
    def captured_event(self):
        raw = (FIXTURES / 'qmp-pre-greeting-resume.jsonl').read_bytes()
        provenance = json.loads((FIXTURES / 'qmp-pre-greeting-resume.json').read_text())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), provenance['capture_sha256'])
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['direction'], 'receive')
        self.assertEqual(rows[0]['value']['event'], 'RESUME')
        return rows[0]['value']

    def test_captured_resume_before_greeting(self):
        event = self.captured_event()
        with peer([event, GREETING]) as (root, commands):
            monitor = QMP(root / 'qmp.sock', Alive(), root / 'qmp.jsonl', 1)
            try:
                self.assertEqual(monitor.command('query-status'), {'running': True})
            finally:
                monitor.close()
            records = [json.loads(line) for line in (root / 'qmp.jsonl').read_text().splitlines()]
            self.assertEqual([row['value'] for row in records[:2]], [event, GREETING])
            self.assertEqual([command['execute'] for command in commands],
                             ['qmp_capabilities', 'query-status'])

    def test_greeting_first(self):
        with peer([GREETING]) as (root, commands):
            monitor = QMP(root / 'qmp.sock', Alive(), root / 'qmp.jsonl', 1)
            try:
                self.assertEqual(monitor.command('query-status'), {'running': True})
            finally:
                monitor.close()
            self.assertEqual(len(commands), 2)

    def test_fragmented_early_event_and_greeting(self):
        with peer([self.captured_event(), GREETING], fragment=7, delay=.001) as (root, _):
            monitor = QMP(root / 'qmp.sock', Alive(), root / 'qmp.jsonl', 1)
            try:
                self.assertEqual(monitor.command('query-status'), {'running': True})
            finally:
                monitor.close()

    def test_event_during_capability_response(self):
        with peer([GREETING], cap_event=self.captured_event()) as (root, _):
            monitor = QMP(root / 'qmp.sock', Alive(), root / 'qmp.jsonl', 1)
            try:
                self.assertEqual(monitor.command('query-status'), {'running': True})
            finally:
                monitor.close()

    def test_event_without_greeting_still_rejects_eof(self):
        with peer([self.captured_event()], close_after_messages=True) as (root, commands):
            with self.assertRaisesRegex(RuntimeError, 'QMP closed before its response'):
                monitor = QMP(root / 'qmp.sock', Alive(), root / 'qmp.jsonl', 1)
                monitor.close()
            self.assertFalse(commands)

    def test_event_stream_does_not_extend_original_deadline(self):
        with peer([self.captured_event()] * 30, delay=.02,
                  close_after_messages=True) as (root, commands):
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                monitor = QMP(root / 'qmp.sock', Alive(), root / 'qmp.jsonl', .08)
                monitor.close()
            self.assertLess(time.monotonic() - started, .5)
            self.assertFalse(commands)

    def test_unexpected_messages_are_not_skipped(self):
        for message in ({'return': {}, 'id': 99}, {'event': 'RESUME', 'return': {}},
                        {'event': None}, {'error': {'class': 'GenericError'}}):
            with self.subTest(message=message), peer([message, GREETING]) as (root, commands):
                with self.assertRaisesRegex(RuntimeError, 'QMP greeting is missing'):
                    monitor = QMP(root / 'qmp.sock', Alive(), root / 'qmp.jsonl', 1)
                    monitor.close()
                self.assertFalse(commands)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Replay normal console prompts, private writes and authenticated elevation."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from normal_login import ConsoleLogin, PASSWORD

PROVISION = (b'Administrator name: admin\r\nNew password: \r\nConfirm password: \r\n'
             b'Administrator created. Please log in.\r\n')
SESSION = (b'login: admin\r\nPassword: \r\n'
           b'ACCOUNT_DESKTOP_READY uid=1000 server=9 clients=12\r\n'
           b'exec pid=8 /bin/bash (dynamic musl)\r\n\x1b[?2004hbash-5.2$ ')


class NormalLoginTests(unittest.TestCase):
    def replay(self, capture):
        writes = []
        login = ConsoleLogin(writes.append)
        for count in range(len(capture) + 1):
            login.consume(capture[:count])
        return login, writes

    def test_first_boot_at_every_byte_boundary(self):
        login, writes = self.replay(PROVISION + SESSION)
        self.assertTrue(login.ready)
        self.assertEqual(writes, [b'admin\n', PASSWORD + b'\n', PASSWORD + b'\n',
                                  b'admin\n', PASSWORD + b'\n'])

    def test_preserved_account_skips_provisioning(self):
        login, writes = self.replay(SESSION)
        self.assertTrue(login.ready)
        self.assertEqual(writes, [b'admin\n', PASSWORD + b'\n'])

    def test_no_command_before_authenticated_desktop_and_shell(self):
        login, writes = self.replay(b'login: admin\nPassword: \n')
        self.assertFalse(login.ready)
        with self.assertRaises(RuntimeError):
            login.elevate('/bin/true')
        self.assertEqual(len(writes), 2)

    def test_elevation_uses_separate_private_prompt(self):
        login, writes = self.replay(SESSION)
        login.elevate('echo one && echo two')
        self.assertNotIn(PASSWORD, writes[-1])
        self.assertIn(b"sh -c 'echo one && echo two'", writes[-1])
        for count in range(len(b'Password: ') + 1):
            login.consume(SESSION + b'Password: '[:count])
        self.assertEqual(writes[-1], PASSWORD + b'\n')
        self.assertEqual(login.stage, 'command')
        login.consume(SESSION + b'Password: \n\x1b[?2004hbash-5.2$ ')
        self.assertEqual(login.stage, 'ready')

    def test_password_echo_and_session_loss_are_errors(self):
        with self.assertRaises(RuntimeError):
            self.replay(SESSION + PASSWORD)
        with self.assertRaises(RuntimeError):
            self.replay(SESSION + b'login: ')

    def test_next_elevation_waits_for_actual_shell_prompt(self):
        login, writes = self.replay(SESSION)
        login.elevate('/bin/init-supervision desktop-after 28 3 2')
        progress = SESSION + (b'Password: \nexec pid=38 /bin/init-supervision (static ELF)\n'
                              b'INIT_OBSERVER_PASS phase=desktop-after pid=28 monotonic_ms=53690\n')
        login.consume(progress)
        count = len(writes)
        login.elevate('/bin/init-supervision stop 28 3 2')
        self.assertEqual(len(writes), count, 'the prior sudo child has not returned the terminal')
        prompt = b'\x1b[?2004hbash-5.2$ '
        for size in range(len(prompt)):
            login.consume(progress + prompt[:size])
            self.assertEqual(len(writes), count)
        login.consume(progress + prompt)
        self.assertEqual(len(writes), count + 1)
        self.assertIn(b'init-supervision stop 28 3 2', writes[-1])

    def test_ordinary_command_queues_after_child_progress(self):
        login, writes = self.replay(SESSION)
        login.command('/bin/first\n')
        count = len(writes)
        progress = SESSION + b'CHILD_PASS $ \n'
        login.consume(progress)
        login.command('/bin/second')
        self.assertEqual(len(writes), count)
        login.consume(progress + b'\x1b[?2004hbash-5.2$ ')
        self.assertEqual(writes[-1], b'/bin/second\n')

    def test_pending_command_is_never_overwritten(self):
        login, writes = self.replay(SESSION)
        login.command('/bin/first')
        login.command('/bin/second')
        with self.assertRaises(RuntimeError):
            login.command('/bin/third')
        self.assertEqual(writes[-1], b'/bin/first\n')

    def test_session_loss_while_waiting_for_command_return(self):
        login, writes = self.replay(SESSION)
        login.command('/bin/first')
        with self.assertRaises(RuntimeError):
            login.consume(SESSION + b'login: ')

    def test_queued_command_waits_for_complete_interrupted_prompt(self):
        login, writes = self.replay(SESSION)
        login.command('/bin/first')
        login.command('/bin/second')
        count = len(writes)
        raw = (Path(__file__).parent / 'fixtures/normal-console/interrupted-prompt.txt').read_bytes()
        complete = raw.index(b' unimplemented syscall') + 1
        for size in range(complete):
            login.consume(SESSION + raw[:size])
            self.assertEqual(len(writes), count)
        login.consume(SESSION + raw[:complete])
        self.assertEqual(writes[-1], b'/bin/second\n')
        self.assertEqual(len(writes), count + 1)


if __name__ == '__main__':
    unittest.main()

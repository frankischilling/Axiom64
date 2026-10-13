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
           b'exec pid=8 /bin/bash (dynamic musl)\r\nbash-5.2$ ')


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
        self.assertEqual(login.stage, 'ready')

    def test_password_echo_and_session_loss_are_errors(self):
        with self.assertRaises(RuntimeError):
            self.replay(SESSION + PASSWORD)
        with self.assertRaises(RuntimeError):
            self.replay(SESSION + b'login: ')


if __name__ == '__main__':
    unittest.main()

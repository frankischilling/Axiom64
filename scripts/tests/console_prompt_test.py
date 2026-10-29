#!/usr/bin/env python3
"""Replay actual kernel-interrupted Bash prompts without accepting child progress."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console_prompt import shell_prompt_end

FIXTURE = Path(__file__).parent / 'fixtures/normal-console/interrupted-prompt.txt'
SUPERVISION = Path(__file__).parent / 'fixtures/normal-console/supervision-interrupted-prompt.txt'


class ConsolePromptTests(unittest.TestCase):
    def test_actual_interrupted_prompt_at_every_byte_boundary(self):
        raw = FIXTURE.read_bytes()
        complete = raw.index(b' unimplemented syscall') + 1
        for size in range(complete):
            self.assertIsNone(shell_prompt_end(raw[:size]), 'an unfinished prompt cannot release input')
        for size in range(complete, len(raw) + 1):
            self.assertEqual(shell_prompt_end(raw[:size]), complete, 'retain the original serial offset')

    def test_contiguous_primary_prompt(self):
        raw = b'child\n\x1b[?2004hbash-5.2$ trailing'
        self.assertEqual(shell_prompt_end(raw), raw.index(b' trailing') + 1)
        self.assertIsNone(shell_prompt_end(raw, len(raw)))

    def test_actual_supervision_prompt_at_every_byte_boundary(self):
        raw = SUPERVISION.read_bytes()
        prefix = b'INIT_OBSERVER_PASS phase=kill pid=2 monotonic_ms=9060\r\n'
        for size in range(len(raw)):
            self.assertIsNone(shell_prompt_end(prefix + raw[:size], len(prefix)),
                              'PID1 progress cannot release an incomplete ordinary prompt')
        expected = len(prefix) + len(raw)
        self.assertEqual(shell_prompt_end(prefix + raw, len(prefix)), expected)
        self.assertEqual(shell_prompt_end(prefix + raw + b'exec pid=28 /sbin/network-manager (static ELF)\r\n',
                                          len(prefix)), expected)

    def test_each_complete_pid1_supervision_record_can_interrupt_a_prompt(self):
        records = [b'Network manager exited status=9; retrying after one second.\r\n',
                   b'INIT_MANAGER_REAP pid=2 status=9 monotonic_ms=9110\r\n',
                   b'INIT_MANAGER_SPAWN pid=28 monotonic_ms=10110\r\n']
        for record in records:
            raw = b'\x1b[?2004h' + record + b'bash-5.2$ '
            with self.subTest(record=record):
                self.assertEqual(shell_prompt_end(raw), len(raw))

    def test_unknown_or_incomplete_supervision_output_cannot_join_a_prompt(self):
        records = [b'Network manager exited status=x; retrying after one second.\r\n',
                   b'Network manager exited status=9; retrying after one second.',
                   b'INIT_MANAGER_REAP pid=2 status=9 monotonic_ms=9110',
                   b'INIT_MANAGER_REAP pid=2 status=9 monotonic_ms=9110 extra\r\n',
                   b'INIT_MANAGER_SPAWN pid=unknown monotonic_ms=10110\r\n',
                   b'INIT_OBSERVER_PASS phase=kill pid=2 monotonic_ms=9060\r\n',
                   b'CHILD_PASS $ \r\n']
        for record in records:
            self.assertIsNone(shell_prompt_end(b'\x1b[?2004h' + record + b'bash-5.2$ '))

    def test_child_output_and_incomplete_prompts_do_not_release_input(self):
        for raw in (b'CHILD_PASS $ \n', b'bash-5.2$ ', b'\x1b[?2004h',
                    b'\x1b[?2004hbash-5.2$', b'\x1b[?2004hbash-5.2$unknown\n '):
            self.assertIsNone(shell_prompt_end(raw))


if __name__ == '__main__':
    unittest.main()

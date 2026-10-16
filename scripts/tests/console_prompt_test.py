#!/usr/bin/env python3
"""Replay actual kernel-interrupted Bash prompts without accepting child progress."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from console_prompt import shell_prompt_end

FIXTURE = Path(__file__).parent / 'fixtures/normal-console/interrupted-prompt.txt'


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

    def test_child_output_and_incomplete_prompts_do_not_release_input(self):
        for raw in (b'CHILD_PASS $ \n', b'bash-5.2$ ', b'\x1b[?2004h',
                    b'\x1b[?2004hbash-5.2$', b'\x1b[?2004hbash-5.2$unknown\n '):
            self.assertIsNone(shell_prompt_end(raw))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Replay premature console echo and check real shell acknowledgement output."""
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from desktop_console import desktop_complete, desktop_test_command

COMPLETE = {b"NORMAL_BOOT_PASS", b"WINDOW_MANAGER_PASS", b"XTERM_WINDOW_PASS",
            b"X11_KEYBOARD_PASS", b"DESKTOP_CAPTURE_READY"}


class DesktopConsoleTests(unittest.TestCase):
    def test_captured_premature_acknowledgement(self):
        # The failed UEFI log has this standalone marker before Xorg has started.
        lines = {b"exec pid=4 /bin/busybox (static ELF)", b"NORMAL_BOOT_PASS",
                 b"exec pid=5 /bin/rm (static ELF)"}
        self.assertFalse(desktop_complete(lines, False, False))
        self.assertFalse(desktop_complete(lines, True, True))

    def test_requires_every_actual_acceptance(self):
        self.assertTrue(desktop_complete(COMPLETE, True, True))
        self.assertFalse(desktop_complete(COMPLETE, False, True))
        self.assertFalse(desktop_complete(COMPLETE, True, False))
        for marker in COMPLETE:
            with self.subTest(missing=marker):
                self.assertFalse(desktop_complete(COMPLETE - {marker}, True, True))

    def test_input_echo_cannot_contain_an_acknowledgement(self):
        command = desktop_test_command()
        for marker in COMPLETE | {b"DESKTOP_INPUT_READY"}:
            self.assertNotIn(marker, command)
        self.assertTrue(command.endswith(b"\n"))

    def test_generated_command_emits_real_acknowledgements(self):
        with tempfile.TemporaryDirectory(prefix="axiom64-desktop-console-") as temporary:
            root = Path(temporary)
            for filename in ("xterm-ready", "x11-input-pass"):
                (root / filename).touch()
            probe = root / "probe.sh"
            probe.write_text("#!/bin/sh\nprintf 'WINDOW_MANAGER_PASS\\nXTERM_WINDOW_PASS\\n'\n")
            command = desktop_test_command().decode().replace(
                "/bin/x11-probe", "sh " + shlex.quote(str(probe)))
            for filename in ("xterm-ready", "x11-input-pass"):
                command = command.replace("/tmp/" + filename, shlex.quote(str(root / filename)))
            output = subprocess.check_output(["sh", "-c", command], timeout=5)
            lines = {line.strip() for line in output.splitlines()}
            self.assertEqual(lines, COMPLETE | {b"DESKTOP_INPUT_READY"})
            self.assertTrue(desktop_complete(lines, True, True))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Execute the terminal launcher on real owned, foreign and background Linux PTYs."""
import hashlib
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DesktopTerminalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid():
            raise RuntimeError('this isolated identity test requires root')
        cls.temporary = tempfile.TemporaryDirectory(prefix='axiom64-desktop-terminal-')
        cls.addClassCleanup(cls.temporary.cleanup)
        folder = Path(cls.temporary.name)
        folder.chmod(0o711)
        cls.binary = folder / 'terminal'
        source = ROOT / 'userspace/desktop/terminal.c'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(source),
                        '-o', str(cls.binary)], check=True)
        cls.shell = folder / 'shell-observer'
        cls.shell.write_text('''#!/usr/bin/python3
import ctypes, os, stat, sys
assert sys.argv[1:] == ['-l']
assert os.getresuid() == (1000, 1000, 1000)
assert os.getresgid() == (1000, 1000, 1000)
value = os.fstat(0)
assert os.isatty(0) and (value.st_uid, value.st_gid) == (1000, 1000)
assert stat.S_IMODE(value.st_mode) == 0o600
assert os.umask(0o077) == 0o077
assert ctypes.CDLL(None).tcgetsid(0) == os.getsid(0)
assert os.tcgetpgrp(0) == os.getpgrp()
print('DESKTOP_TERMINAL_SHELL_PASS')
''')
        cls.shell.chmod(0o755)
        cls.environment = dict(os.environ, SHELL=str(cls.shell), USER='fixture')
        print('DESKTOP_TERMINAL_NATIVE_PROVENANCE source_sha256=' +
              hashlib.sha256(source.read_bytes()).hexdigest() + ' binary_sha256=' +
              hashlib.sha256(cls.binary.read_bytes()).hexdigest(), flush=True)

    @staticmethod
    def drop(uid=1000):
        os.setgroups([])
        os.setresgid(uid, uid, uid)
        os.setresuid(uid, uid, uid)

    def terminal(self, owner=1000, group=1000, background=False, user=1000):
        master, slave = os.openpty()
        os.fchown(slave, owner, group)
        os.fchmod(slave, 0o622)
        child = os.fork()
        if not child:
            try:
                os.close(master)
                os.login_tty(slave)
                if background:
                    leaf = os.fork()
                    if leaf:
                        _, status = os.waitpid(leaf, 0)
                        os._exit(os.waitstatus_to_exitcode(status))
                    os.setpgid(0, 0)
                self.drop(user)
                environment = dict(self.environment, SHELL='/bin/true') if not user else self.environment
                os.execve(str(self.binary), [str(self.binary)], environment)
            except BaseException:
                os._exit(126)
        os.close(slave)
        output = bytearray()
        status = None
        started = time.monotonic()
        try:
            while status is None:
                ready, _, _ = select.select([master], [], [], .05)
                if ready:
                    try:
                        output.extend(os.read(master, 4096))
                    except OSError:
                        pass
                completed, observed = os.waitpid(child, os.WNOHANG)
                if completed:
                    status = observed
                self.assertLess(time.monotonic() - started, 5, 'launcher deadline')
            return os.waitstatus_to_exitcode(status), bytes(output)
        finally:
            if status is None:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
            os.close(master)

    def test_owned_terminal_is_private_before_selected_shell(self):
        result, output = self.terminal()
        self.assertEqual(result, 0)
        self.assertIn(b'DESKTOP_TERMINAL_SHELL_PASS', output)

    def test_foreign_retained_descriptor_is_denied(self):
        result, output = self.terminal(owner=1001)
        self.assertEqual(result, 1)
        self.assertNotIn(b'Signed in as', output)
        self.assertNotIn(b'DESKTOP_TERMINAL_SHELL_PASS', output)

    def test_foreign_group_is_denied(self):
        result, output = self.terminal(group=1001)
        self.assertEqual(result, 1)
        self.assertNotIn(b'Signed in as', output)
        self.assertNotIn(b'DESKTOP_TERMINAL_SHELL_PASS', output)

    def test_background_group_is_denied(self):
        result, output = self.terminal(background=True)
        self.assertEqual(result, 1)
        self.assertNotIn(b'Signed in as', output)
        self.assertNotIn(b'DESKTOP_TERMINAL_SHELL_PASS', output)

    def test_root_owned_terminal_is_denied(self):
        result, output = self.terminal(owner=0, group=0, user=0)
        self.assertEqual(result, 1)
        self.assertNotIn(b'Signed in as', output)

    def test_root_and_nonterminal_are_denied(self):
        for enter in (None, self.drop):
            result = subprocess.run([str(self.binary)], env=self.environment, stdin=subprocess.DEVNULL,
                preexec_fn=enter, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b'DESKTOP_TERMINAL_SHELL_PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()

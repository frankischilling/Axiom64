#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check authority parsing and actual Xvfb/Xlib cookie acceptance and denial."""
import ctypes as C
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DesktopAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='axiom64-desktop-authority-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        cls.folder.chmod(0o711)
        shared = cls.folder / 'authority.so'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared',
                        '-fPIC', str(ROOT / 'userspace/desktop/authority.c'), '-o', str(shared)],
                       check=True)
        cls.api = C.CDLL(str(shared), use_errno=True)
        cls.api.desktop_authority_write.argtypes = [C.c_int, C.c_uint, C.c_void_p]
        cls.api.desktop_authority_write.restype = C.c_int
        cls.api.desktop_authority_read.argtypes = [C.c_char_p, C.c_uint, C.c_void_p]
        cls.api.desktop_authority_read.restype = C.c_int
        cls.cookie = os.getrandom(16)

    def write(self, path, display, cookie=None):
        value = C.create_string_buffer(self.cookie if cookie is None else cookie)
        with path.open('wb') as output:
            self.assertEqual(self.api.desktop_authority_write(output.fileno(), display, value), 0)
        path.chmod(0o600)

    def read(self, path, display):
        value = C.create_string_buffer(b'\xff' * 16, 16)
        result = self.api.desktop_authority_read(os.fsencode(path), display, value)
        if result:
            self.assertTrue(value.raw == bytes(16), 'failed read retained secret bytes')
        else:
            self.assertTrue(value.raw == self.cookie, 'successful read changed the cookie')
        return result

    def test_bounded_record_and_bad_paths(self):
        valid = self.folder / 'parser.auth'
        self.write(valid, 65535)
        self.assertEqual(self.read(valid, 65535), 0)
        original = valid.read_bytes()
        bad = self.folder / 'bad.auth'
        bad.chmod(0o600) if bad.exists() else None
        mutations = [original[:size] for size in range(len(original))]
        mutations += [original + b'\0', original + original, bytes(513),
                      b'\0\0' + original[2:], original[:2] + b'\xff\xff' + original[4:]]
        for payload in mutations:
            bad.write_bytes(payload)
            self.assertEqual(self.read(bad, 65535), -1)
        # Each field is checked, including host, decimal display, protocol and cookie length.
        at = 2
        for field in range(4):
            length = int.from_bytes(original[at:at + 2], 'big')
            edited = bytearray(original)
            if field == 3:
                edited[at + 1] = 15
            else:
                edited[at + 2] ^= 1
            bad.write_bytes(edited)
            self.assertEqual(self.read(bad, 65535), -1)
            at += 2 + length
        self.assertEqual(self.read(valid, 0), -1)
        self.assertEqual(self.read(valid, 65536), -1)
        self.assertEqual(self.read(self.folder / 'missing.auth', 65535), -1)
        self.assertEqual(self.read(self.folder, 65535), -1)
        link = self.folder / 'symlink.auth'
        link.symlink_to(valid)
        self.addCleanup(link.unlink)
        self.assertEqual(self.read(link, 65535), -1)
        hard = self.folder / 'hardlink.auth'
        os.link(valid, hard)
        self.addCleanup(hard.unlink)
        self.assertEqual(self.read(valid, 65535), -1)

    def test_real_server_xlib_and_user_denials(self):
        auth = self.folder / 'server.auth'
        self.write(auth, 0)
        read_fd, write_fd = os.pipe()
        with (self.folder / 'xvfb.log').open('wb') as log:
            try:
                server = subprocess.Popen(['Xvfb', '-displayfd', str(write_fd), '-screen', '0',
                    '1024x768x24', '-nolisten', 'tcp', '-auth', str(auth)], pass_fds=(write_fd,),
                    stdout=log, stderr=log)
                self.addCleanup(self.stop, server)
                os.close(write_fd)
                write_fd = -1
                with selectors.DefaultSelector() as ready:
                    ready.register(read_fd, selectors.EVENT_READ)
                    self.assertTrue(ready.select(5), 'owned Xvfb did not become ready')
                    number = os.read(read_fd, 32).strip()
                    self.assertTrue(number.isdigit(), 'invalid display number: ' +
                                    (self.folder / 'xvfb.log').read_text()[:2000])
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)
        display = int(number)
        self.write(auth, display)
        probe = self.folder / 'probe'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
            '-DAXIOM64_X11_SOCKET="/tmp/.X11-unix/X' + str(display) + '"',
            '-DAXIOM64_X11_DISPLAY=' + str(display), str(ROOT / 'userspace/tests/desktop/probe.c'),
            str(ROOT / 'userspace/desktop/authority.c'), '-o', str(probe)], check=True)
        environment = dict(os.environ, DISPLAY=':' + str(display), XAUTHORITY=str(auth))
        accepted = subprocess.run(['xdpyinfo'], env=environment, capture_output=True, timeout=5)
        self.assertEqual(accepted.returncode, 0, 'real Xlib rejected the generated record')
        self.assertIn(b'number of screens:', accepted.stdout)
        self.assertEqual(subprocess.run([str(probe), '--ready'], env=environment,
            capture_output=True, timeout=5).returncode, 0)
        denied = dict(environment, XAUTHORITY='')
        self.assertEqual(subprocess.run([str(probe), '--ready'], env=denied,
            capture_output=True, timeout=5).returncode, 1)
        wrong = self.folder / 'wrong.auth'
        self.write(wrong, display, bytes(byte ^ 0xff for byte in self.cookie))
        self.assertEqual(subprocess.run([str(probe), '--ready'], env=dict(environment,
            XAUTHORITY=str(wrong)), capture_output=True, timeout=5).returncode, 1)
        if os.geteuid() == 0:
            client = self.folder / 'client.auth'
            self.write(client, display)
            os.chown(client, 1000, 1000)
            client.chmod(0o400)

            def drop(uid):
                def enter():
                    os.setgroups([])
                    os.setresgid(uid, uid, uid)
                    os.setresuid(uid, uid, uid)
                return enter

            client_environment = dict(environment, XAUTHORITY=str(client))
            for uid, expected in ((1000, 0), (1001, 1)):
                self.assertEqual(subprocess.run([str(probe), '--ready'], env=client_environment,
                    preexec_fn=drop(uid), capture_output=True, timeout=5).returncode, expected)
        else:
            self.fail('run in the isolated root build host to exercise both ordinary identities')

    @staticmethod
    def stop(server):
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


if __name__ == '__main__':
    if sys.argv[1:] == ['--isolated']:
        raise SystemExit(subprocess.run(['unshare', '--mount', '--net', '--pid', '--fork',
            '--mount-proc', sys.executable, str(Path(__file__).resolve()), '--inside']).returncode)
    if sys.argv[1:] == ['--inside']:
        subprocess.run(['mount', '--make-rprivate', '/'], check=True)
        subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', '/tmp'], check=True)
        sys.argv = sys.argv[:1]
    unittest.main()

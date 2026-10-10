#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real desktop probe against mapped windows on an owned Xvfb."""
import ctypes as C
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ClassHint(C.Structure):
    _fields_ = [('res_name', C.c_char_p), ('res_class', C.c_char_p)]


def xlib():
    library = C.CDLL('libX11.so.6')
    signatures = {
        'XOpenDisplay': ([C.c_char_p], C.c_void_p),
        'XDefaultRootWindow': ([C.c_void_p], C.c_ulong),
        'XSelectInput': ([C.c_void_p, C.c_ulong, C.c_long], C.c_int),
        'XCreateSimpleWindow': ([C.c_void_p, C.c_ulong, C.c_int, C.c_int,
                                C.c_uint, C.c_uint, C.c_uint, C.c_ulong, C.c_ulong], C.c_ulong),
        'XSetClassHint': ([C.c_void_p, C.c_ulong, C.POINTER(ClassHint)], C.c_int),
        'XMapWindow': ([C.c_void_p, C.c_ulong], C.c_int),
        'XClearWindow': ([C.c_void_p, C.c_ulong], C.c_int),
        'XSync': ([C.c_void_p, C.c_int], C.c_int),
        'XCreateGC': ([C.c_void_p, C.c_ulong, C.c_ulong, C.c_void_p], C.c_void_p),
        'XSetForeground': ([C.c_void_p, C.c_void_p, C.c_ulong], C.c_int),
        'XFillRectangle': ([C.c_void_p, C.c_ulong, C.c_void_p, C.c_int, C.c_int,
                            C.c_uint, C.c_uint], C.c_int),
        'XFreeGC': ([C.c_void_p, C.c_void_p], C.c_int),
        'XDestroyWindow': ([C.c_void_p, C.c_ulong], C.c_int),
        'XCloseDisplay': ([C.c_void_p], C.c_int),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result
    return library


class DesktopVisualTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='axiom64-desktop-visual-')
        cls.addClassCleanup(cls.temporary.cleanup)
        folder = Path(cls.temporary.name)
        with (folder / 'xvfb.log').open('wb') as log:
            read_fd, write_fd = os.pipe()
            try:
                cls.server = subprocess.Popen(
                    ['Xvfb', '-displayfd', str(write_fd), '-screen', '0', '1024x768x24',
                     '-nolisten', 'tcp', '-ac'],
                    pass_fds=(write_fd,), stdout=log, stderr=log)
                cls.addClassCleanup(cls.stop_server)
                os.close(write_fd)
                write_fd = -1
                with selectors.DefaultSelector() as ready:
                    ready.register(read_fd, selectors.EVENT_READ)
                    if not ready.select(5):
                        raise RuntimeError('owned Xvfb startup deadline: ' +
                                           (folder / 'xvfb.log').read_text()[:1000])
                    number = os.read(read_fd, 32).strip()
                    if not number.isdigit():
                        raise RuntimeError('owned Xvfb startup failure: ' +
                                           (folder / 'xvfb.log').read_text()[:1000])
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)
        cls.x = xlib()
        cls.display = cls.x.XOpenDisplay(b':' + number)
        if not cls.display:
            raise RuntimeError('cannot connect to owned Xvfb')
        cls.addClassCleanup(cls.x.XCloseDisplay, cls.display)
        cls.root = cls.x.XDefaultRootWindow(cls.display)
        cls.binary = folder / 'probe'
        subprocess.run(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        '-DAXIOM64_X11_SOCKET="/tmp/.X11-unix/X' + number.decode() + '"',
                        str(ROOT / 'userspace/tests/desktop/probe.c'), '-o', str(cls.binary)],
                       check=True)

    @classmethod
    def stop_server(cls):
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.wait()

    def window(self, terminal=True):
        window = self.x.XCreateSimpleWindow(self.display, self.root, 40, 52, 500, 300,
                                            0, 0, 0xffffff)
        hint = ClassHint(b'xterm' if terminal else b'decoy', b'XTerm' if terminal else b'Decoy')
        self.x.XSetClassHint(self.display, window, C.byref(hint))
        self.x.XMapWindow(self.display, window)
        self.x.XClearWindow(self.display, window)
        gc = self.x.XCreateGC(self.display, window, 0, None)
        self.x.XSetForeground(self.display, gc, 0)
        self.x.XSync(self.display, 0)
        self.addCleanup(self.x.XDestroyWindow, self.display, window)
        self.addCleanup(self.x.XFreeGC, self.display, gc)
        return window, gc

    def setUp(self):
        self.x.XSelectInput(self.display, self.root, 1 << 20)
        # A painted nonterminal must not satisfy the terminal image check.
        decoy = self.window(False)
        self.paint(decoy)
        self.terminal = self.window()

    def paint(self, target, size=20):
        window, gc = target
        self.x.XFillRectangle(self.display, window, gc, 20, 20, size, size)
        self.x.XSync(self.display, 0)

    def invoke(self):
        process = subprocess.Popen([str(self.binary), '--desktop'], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        self.addCleanup(self.stop_probe, process)
        return process

    @staticmethod
    def stop_probe(process):
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()

    def accepted(self, process, output, error):
        self.assertEqual(process.returncode, 0, (output + error).decode())
        self.assertIn(b'WINDOW_MANAGER_PASS\n', output)
        self.assertIn(b'XTERM_WINDOW_PASS\n', output)
        self.assertIn(f'XTERM_WINDOW_ID window={self.terminal[0]}\n'.encode(), output)
        match = re.search(rb'XTERM_IMAGE_READY window=(\d+) attempts=(\d+) different=(\d+)', output)
        self.assertIsNotNone(match, output)
        self.assertEqual(int(match[1]), self.terminal[0])
        self.assertEqual(int(match[3]), 400)
        return int(match[2])

    def test_painted_window(self):
        self.paint(self.terminal)
        process = self.invoke()
        output, error = process.communicate(timeout=4)
        self.assertEqual(self.accepted(process, output, error), 1)

    def test_paint_after_first_uniform_image(self):
        process = self.invoke()
        prefix = bytearray()
        deadline = time.monotonic() + 1
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            while b'XTERM_IMAGE_WAIT ' not in prefix and time.monotonic() < deadline:
                if not ready.select(max(0, deadline - time.monotonic())):
                    break
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                prefix.extend(chunk)
        if b'XTERM_IMAGE_WAIT ' in prefix:
            self.assertIn(f'window={self.terminal[0]} different=0\n'.encode(), prefix)
            time.sleep(.35)
            self.assertIsNone(process.poll(), 'probe must remain alive before actual painting')
            self.paint(self.terminal)
        output, error = process.communicate(timeout=4)
        attempts = self.accepted(process, bytes(prefix) + output, error)
        self.assertGreater(attempts, 1)

    def rejected_image(self, size=None):
        if size:
            self.paint(self.terminal, size)
        started = time.monotonic()
        process = self.invoke()
        output, error = process.communicate(timeout=4)
        elapsed = time.monotonic() - started
        self.assertEqual(process.returncode, 1, (output + error).decode())
        self.assertIn(b'different > 100', error)
        self.assertNotIn(b'XTERM_WINDOW_PASS', output)
        self.assertNotIn(b'XTERM_WINDOW_ID', output)
        self.assertLess(elapsed, 3.5)

    def test_permanently_uniform_window(self):
        self.rejected_image()

    def test_one_hundred_different_pixels_still_fail(self):
        self.rejected_image(10)

    def test_window_manager_is_still_required(self):
        self.paint(self.terminal)
        self.x.XSelectInput(self.display, self.root, 0)
        self.x.XSync(self.display, 0)
        process = self.invoke()
        output, error = process.communicate(timeout=4)
        self.assertEqual(process.returncode, 1, (output + error).decode())
        self.assertIn(b'length >= 12', error)
        self.assertNotIn(b'WINDOW_MANAGER_PASS', output)
        self.assertNotIn(b'XTERM_WINDOW_ID', output)


if __name__ == '__main__':
    unittest.main()

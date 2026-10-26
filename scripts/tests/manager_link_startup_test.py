#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Preserve real emulator startup failures before monitor initialization."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import manager_link_test


class ManagerStartupTest(unittest.TestCase):
    def test_actual_qemu_debugger_bind_failure_keeps_stderr_and_command(self):
        real_popen = subprocess.Popen
        commands = []
        with tempfile.TemporaryDirectory(prefix='axiom-manager-startup-') as temporary, socket.socket() as owner:
            root = Path(temporary)
            (root / 'build').mkdir()
            image = root / 'empty.iso'
            image.write_bytes(bytes(32768))
            owner.bind(('127.0.0.1', 0))
            owner.listen(1)
            endpoint = f'tcp:127.0.0.1:{owner.getsockname()[1]}'

            def start(command, **kwargs):
                # Force one real startup error, independently of endpoint choice.
                actual = list(command)
                actual[actual.index('-gdb') + 1] = endpoint
                commands.append(actual)
                return real_popen(actual, **kwargs)

            with patch.object(manager_link_test, 'ROOT', root), \
                    patch.object(manager_link_test.subprocess, 'Popen', side_effect=start), \
                    redirect_stdout(io.StringIO()):
                result = manager_link_test.run('static', 'rx-length', 0, 'bios', 'modern', 220, image)
            self.assertFalse(result['passed'])
            self.assertEqual(result['returncode'], 1)
            text = (root / 'build' / result['log']).read_text()
            self.assertIn('Address already in use', text)
            self.assertIn('gdb', text.lower())
            packets = json.loads((root / 'build' / result['packets']).read_text())
            self.assertIn('emulator', packets)
            self.assertEqual(packets['emulator']['returncode'], 1)
            self.assertEqual(packets['emulator']['deadline_seconds'], 220)
            # The recorded intended command must use a private Unix endpoint.
            intended = packets['emulator']['command']
            self.assertEqual(intended[intended.index('-gdb') + 1], 'chardev:manager-debug')
            device = intended[intended.index('-chardev') + 1]
            self.assertTrue(device.startswith('socket,path='))
            self.assertIn('/gdb.sock,server=on,wait=off,id=manager-debug', device)
            path = Path(device.split('path=', 1)[1].split(',', 1)[0])
            self.assertTrue(path.parent.name.startswith('axiom64-manager-link-'))
            self.assertFalse(path.parent.exists())
            self.assertEqual(len(commands), 1)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep one owned download image and expose real extractor failures."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from http_download import normal_fixture
from http_download.iso import components


class DownloadImages(unittest.TestCase):
    def test_ram_and_disk_images_transfer_the_generated_output(self):
        for disk_root in (False, True):
            with self.subTest(disk_root=disk_root), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                build = root / 'build'
                build.mkdir()
                (build / 'axiom64.elf').write_bytes(b'actual kernel')
                archive = root / 'root.cpio'
                archive.write_bytes(b'actual fixture archive')
                case = root / 'case'
                case.mkdir()
                generated = []

                def builder(command, **keywords):
                    self.assertEqual(keywords['cwd'], root)
                    target = build / command[command.index('--output-name') + 1]
                    target.write_bytes(b'actual generated image')
                    generated.append(target)
                    return subprocess.CompletedProcess(command, 0)

                def bootstrap(path):
                    path.write_bytes(b'actual bootstrap archive')

                with patch.object(normal_fixture, 'ROOT', root), \
                        patch.object(normal_fixture, 'bootstrap', side_effect=bootstrap), \
                        patch.object(normal_fixture.subprocess, 'run', side_effect=builder):
                    image = normal_fixture.image(case / 'image', archive, disk_root)
                self.assertEqual(image.read_bytes(), b'actual generated image')
                self.assertFalse(generated[0].exists(), 'the generated image must not remain as a duplicate')
                record = json.loads((image.parent / 'inputs.json').read_text())
                self.assertEqual(record['image']['sha256'], hashlib.sha256(image.read_bytes()).hexdigest())
                expected = b'actual bootstrap archive' if disk_root else archive.read_bytes()
                self.assertEqual(record['initramfs']['sha256'], hashlib.sha256(expected).hexdigest())

    def test_real_extractor_failure_keeps_diagnostics_and_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / 'invalid.iso'
            data = b'not an ISO image'
            image.write_bytes(data)
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                components(image, {})
            error = caught.exception
            self.assertTrue(error.stderr)
            self.assertIn(error.stderr.decode(errors='replace'), '\n'.join(error.__notes__))
            self.assertEqual(image.read_bytes(), data)


if __name__ == '__main__':
    unittest.main()

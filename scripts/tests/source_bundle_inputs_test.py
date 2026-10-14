#!/usr/bin/env python3
"""Keep actual text and binary regression inputs in corresponding-source archives."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import sources

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path('scripts/tests/fixtures/normal-console/interrupted-prompt.txt')
RECOVERY_FIXTURE = Path('scripts/tests/fixtures/ext2-deleted-open-inode.raw.gz')
NAMED_RECOVERY_FIXTURE = Path('scripts/tests/fixtures/ext2-named-retirement.raw.gz')
SYMLINK_RECOVERY_FIXTURE = Path('scripts/tests/fixtures/ext2-named-symlink-retirement.raw.gz')
CLEARED_SYMLINK_FIXTURE = Path('scripts/tests/fixtures/ext2-cleared-named-symlink.raw.gz')
RECOVERY_FIXTURES = (RECOVERY_FIXTURE, NAMED_RECOVERY_FIXTURE, SYMLINK_RECOVERY_FIXTURE, CLEARED_SYMLINK_FIXTURE)


class SourceBundleInputsTests(unittest.TestCase):
    def test_exported_prompt_test_keeps_its_exact_serial_input(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-source-inputs-') as name:
            root = Path(name) / 'source'
            root.mkdir()
            for item in ('sources.lock.json', 'ports.lock.json', 'dependencies.json', 'LICENSE',
                         'Makefile', 'README.md', '.clang-format', '.gitattributes'):
                (root / item).write_bytes(b'fixture\n')
            for folder in ('kernel', 'userspace', 'boot', 'vendor', 'docs'):
                (root / folder).mkdir()
            configuration = root / 'build/busybox-1.37.0/.config'
            configuration.parent.mkdir(parents=True)
            configuration.write_bytes(b'fixture\n')
            for item in (Path('scripts/console_prompt.py'), Path('scripts/tests/console_prompt_test.py'),
                         FIXTURE, *RECOVERY_FIXTURES):
                target = root / item
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / item, target)
            # Third-party kit publication has separate execution/relink gates.
            # This fixture isolates the archive's own scripts and their inputs.
            with patch.object(sources, 'ROOT', root), patch.object(sources, 'gnu_reader_kit'), redirect_stdout(io.StringIO()):
                sources.bundle([])
            extracted = Path(name) / 'extracted'
            with tarfile.open(root / 'build/axiom64-sources.tar') as archive:
                for fixture in (FIXTURE, *RECOVERY_FIXTURES):
                    member = archive.getmember('Axiom64/' + fixture.as_posix())
                    self.assertEqual(archive.extractfile(member).read(), (ROOT / fixture).read_bytes())
                archive.extractall(extracted, filter='data')
            result = subprocess.run([sys.executable, str(extracted / 'Axiom64/scripts/tests/console_prompt_test.py'), '-v'],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

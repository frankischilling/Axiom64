#!/usr/bin/env python3
"""Keep actual text and binary regression inputs in corresponding-source archives."""
from contextlib import redirect_stdout
import io
import json
import os
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
PUBLICATION_HELPER = Path('scripts/ci/storage_evidence.sh')
FIXTURE = Path('scripts/tests/fixtures/normal-console/interrupted-prompt.txt')
RECOVERY_FIXTURE = Path('scripts/tests/fixtures/ext2-deleted-open-inode.raw.gz')
NAMED_RECOVERY_FIXTURE = Path('scripts/tests/fixtures/ext2-named-retirement.raw.gz')
SYMLINK_RECOVERY_FIXTURE = Path('scripts/tests/fixtures/ext2-named-symlink-retirement.raw.gz')
CLEARED_SYMLINK_FIXTURE = Path('scripts/tests/fixtures/ext2-cleared-named-symlink.raw.gz')
DIRECTORY_RECOVERY_FIXTURE = Path('scripts/tests/fixtures/ext2-named-directory-retirement.raw.gz')
CLEARED_DIRECTORY_FIXTURE = Path('scripts/tests/fixtures/ext2-cleared-named-directory.raw.gz')
ACCOUNT_ORACLE_FIXTURES = tuple(Path('scripts/tests/fixtures') / name for name in (
    'account-generation-journal-replay.raw.gz', 'account-generation-journal-replay.json',
    'account-journal-retirement.raw.gz', 'account-journal-retirement.json',
    'account-rotation-journal-retirement.raw.gz', 'account-rotation-journal-retirement.json',
    'account-rotation-journal-allocation.raw.gz', 'account-rotation-journal-allocation.json',
    'qmp-pre-greeting-resume.jsonl', 'qmp-pre-greeting-resume.json',
    'account-management-targets.json', 'account-rotation-targets.json',
    'account-rotation-provisional.json', 'ext2-counter-drift.raw.gz',
    'account-rotation-interrupted-data.txt'))
RECOVERY_FIXTURES = (RECOVERY_FIXTURE, NAMED_RECOVERY_FIXTURE, SYMLINK_RECOVERY_FIXTURE, CLEARED_SYMLINK_FIXTURE,
                     DIRECTORY_RECOVERY_FIXTURE, CLEARED_DIRECTORY_FIXTURE, *ACCOUNT_ORACLE_FIXTURES)


class SourceBundleInputsTests(unittest.TestCase):
    def test_exported_resource_limits_build_and_run_their_actual_native_policies(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-resource-source-inputs-') as name:
            root = Path(name) / 'source'
            root.mkdir()
            for item in ('sources.lock.json', 'ports.lock.json', 'dependencies.json', 'LICENSE',
                         'Makefile', 'README.md', '.clang-format', '.gitattributes'):
                shutil.copyfile(ROOT / item, root / item)
            for folder in ('kernel', 'userspace', 'boot', 'vendor', 'docs', 'scripts'):
                shutil.copytree(ROOT / folder, root / folder)
            configuration = root / 'build/busybox-1.37.0/.config'
            configuration.parent.mkdir(parents=True)
            configuration.write_bytes(b'fixture\n')
            with patch.object(sources, 'ROOT', root), patch.object(sources, 'gnu_reader_kit'), redirect_stdout(io.StringIO()):
                sources.bundle([])
            extracted = Path(name) / 'extracted'
            with tarfile.open(root / 'build/axiom64-sources.tar') as archive:
                for item in ('kernel/include/process/limits.hpp', 'kernel/process/limits.cpp',
                             'kernel/include/mm/stack.hpp', 'kernel/mm/stack.cpp',
                             'scripts/resource_limits_test.py', 'scripts/resource_limits_storage_test.py',
                             'userspace/tests/process/resource-limits.c'):
                    self.assertEqual(archive.extractfile('Axiom64/' + item).read(), (ROOT / item).read_bytes())
                archive.extractall(extracted, filter='data')
            exported = extracted / 'Axiom64'
            result = subprocess.run(['make', '-s', '-j2', 'test-process-limits-policy',
                                     'test-proc-identity-policy', 'test-exec-arguments-policy'],
                                    cwd=exported, env=dict(os.environ, PYTHONPATH=''),
                                    capture_output=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for marker in (b'PROCESS_LIMIT_NATIVE_DIFFERENTIAL_PASS', b'PROC_IDENTITY_KERNEL_PASS',
                           b'EXEC_ARGUMENTS_HOST_PASS'):
                self.assertIn(marker, result.stdout)

    def test_exported_ca_proof_runs_offline_from_actual_published_inputs(self):
        from build_curl import source_inputs as curl_sources
        from ca_bundle import source_inputs as ca_sources
        inputs = [curl_sources(), ca_sources()]
        with tempfile.TemporaryDirectory(prefix='axiom64-ca-source-export-') as temporary:
            root = Path(temporary) / 'source'
            root.mkdir()
            for name in ('sources.lock.json', 'ports.lock.json', 'dependencies.json', 'LICENSE',
                         'Makefile', 'README.md', '.clang-format', '.gitattributes'):
                shutil.copyfile(ROOT / name, root / name)
            shutil.copytree(ROOT / 'scripts', root / 'scripts',
                            ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            for folder in ('kernel', 'userspace', 'boot', 'vendor', 'docs'):
                (root / folder).mkdir()
            configuration = root / 'build/busybox-1.37.0/.config'
            configuration.parent.mkdir(parents=True)
            configuration.write_bytes(b'fixture\n')
            with patch.object(sources, 'ROOT', root), patch.object(sources, 'gnu_reader_kit'), redirect_stdout(io.StringIO()):
                sources.bundle(inputs)
            extracted = Path(temporary) / 'extracted'
            with tarfile.open(root / 'build/axiom64-sources.tar') as archive:
                archive.extractall(extracted, filter='data')
            exported = extracted / 'Axiom64'
            lock = json.loads((exported / 'dependencies.json').read_text())
            paths = {
                'ports/ca-bundle/' + lock['ca_bundle']['archive']: 'downloads/' + lock['ca_bundle']['archive'],
                'ports/ca-bundle/certdata.txt': 'downloads/sources/ca-bundle/certdata.txt',
                'ports/ca-bundle/MPL-2.0.txt': 'downloads/sources/ca-bundle/MPL-2.0.txt',
                'ports/curl-upstream/' + lock['curl']['archive']: 'downloads/' + lock['curl']['archive'],
            }
            for original, relative in paths.items():
                destination = exported / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(extracted / original, destination)
            code = ('import runpy,sys,urllib.request\n'
                    'def offline(*args,**kwargs): raise RuntimeError("source export attempted a network fallback")\n'
                    'urllib.request.urlopen=offline\n'
                    'sys.argv=["scripts/tests/ca_bundle_test.py","-v"]\n'
                    'runpy.run_path(sys.argv[0],run_name="__main__")\n')
            result = subprocess.run([sys.executable, '-c', code], cwd=exported,
                env=dict(os.environ, PYTHONPATH=''), capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_exported_account_oracle_replays_its_actual_retained_inputs(self):
        with tempfile.TemporaryDirectory(prefix='axiom64-account-source-inputs-') as name:
            root = Path(name) / 'source'
            root.mkdir()
            for item in ('sources.lock.json', 'ports.lock.json', 'dependencies.json', 'LICENSE',
                         'Makefile', 'README.md', '.clang-format', '.gitattributes'):
                shutil.copyfile(ROOT / item, root / item)
            for folder in ('kernel', 'userspace', 'boot', 'vendor', 'docs'):
                (root / folder).mkdir()
            configuration = root / 'build/busybox-1.37.0/.config'
            configuration.parent.mkdir(parents=True)
            configuration.write_bytes(b'fixture\n')
            for item in [*(path.relative_to(ROOT) for path in (ROOT / 'scripts').rglob('*.py')),
                         *ACCOUNT_ORACLE_FIXTURES, PUBLICATION_HELPER]:
                target = root / item
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / item, target)
            for item in json.loads((ROOT / 'sources.lock.json').read_text())['musl_local_patches']:
                target = root / item['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / item['path'], target)
            with patch.object(sources, 'ROOT', root), patch.object(sources, 'gnu_reader_kit'), redirect_stdout(io.StringIO()):
                sources.bundle([])
            extracted = Path(name) / 'extracted'
            with tarfile.open(root / 'build/axiom64-sources.tar') as archive:
                for fixture in (*ACCOUNT_ORACLE_FIXTURES, PUBLICATION_HELPER):
                    self.assertEqual(archive.extractfile('Axiom64/' + fixture.as_posix()).read(),
                                     (ROOT / fixture).read_bytes())
                archive.extractall(extracted, filter='data')
            exported = extracted / 'Axiom64'
            for test in ('account_generation_oracle_test.py', 'account_rotation_serial_test.py',
                         'account_rotation_journal_oracle_test.py', 'qmp_greeting_test.py',
                         'path_descriptor_cancellation_test.py', 'crypto_cache_test.py',
                         'host_glibc_sources_test.py', 'http_download_peer_test.py',
                         'http_download_normal_fixture_test.py', 'http_download_normal_dns_test.py',
                         'download_evidence_ownership_test.py', 'http_download_native_process_test.py'):
                result = subprocess.run([sys.executable, 'scripts/tests/' + test, '-v'],
                                        cwd=exported, env=dict(os.environ, PYTHONPATH=''),
                                        capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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
                         FIXTURE, *RECOVERY_FIXTURES, PUBLICATION_HELPER):
                target = root / item
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / item, target)
            # Third-party kit publication has separate execution/relink gates.
            # This fixture isolates the archive's own scripts and their inputs.
            with patch.object(sources, 'ROOT', root), patch.object(sources, 'gnu_reader_kit'), redirect_stdout(io.StringIO()):
                sources.bundle([])
            extracted = Path(name) / 'extracted'
            with tarfile.open(root / 'build/axiom64-sources.tar') as archive:
                for fixture in (FIXTURE, *RECOVERY_FIXTURES, PUBLICATION_HELPER):
                    member = archive.getmember('Axiom64/' + fixture.as_posix())
                    self.assertEqual(archive.extractfile(member).read(), (ROOT / fixture).read_bytes())
                archive.extractall(extracted, filter='data')
            result = subprocess.run([sys.executable, str(extracted / 'Axiom64/scripts/tests/console_prompt_test.py'), '-v'],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

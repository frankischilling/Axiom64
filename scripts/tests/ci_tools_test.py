# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep package restoration bounded, authenticated and fail-closed."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / 'ci/tools.sh'
MOCK = '''#!/usr/bin/env python3
import json,os,pathlib,subprocess,sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['TOOL_CALLS'],'a') as output:output.write(json.dumps([name,*args])+'\\n')
if name=='sudo':
 if args and args[0]=='-n':args=args[1:]
 sys.exit(subprocess.call(args))
if name=='timeout':
 while args and args[0].startswith('-'):args=args[1:]
 sys.exit(subprocess.call(args[1:]))
if name=='apt-get':
 key='OFFLINE_STATUS' if '--no-download' in args else 'UPDATE_STATUS' if 'update' in args else 'INSTALL_STATUS'
 sys.exit(int(os.environ.get(key,'0')))
if name=='dpkg-query':print('installed')
if name=='lsb_release':print(os.environ.get('TEST_DISTRO','Ubuntu') if '-is' in args else os.environ.get('TEST_CODENAME','noble'))
'''


class PackageRestore(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='axiom64-ci-tools-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('sudo', 'timeout', 'apt-get', 'dpkg-query', 'lsb_release'):
            target = self.bin / name
            target.write_text(MOCK)
            target.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        RUNNER_TEMP=str(self.root / 'runner with spaces'), TOOL_CALLS=str(self.root / 'calls.jsonl'))

    def run_helper(self, mode='restore', **environment):
        result = subprocess.run(['bash', str(HELPER), mode], cwd=self.root,
                                env=dict(self.env, **environment), capture_output=True, text=True)
        calls = self.root / 'calls.jsonl'
        return result, [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []

    def bundle(self):
        directory = self.root / 'build/ci-packages'
        directory.mkdir(parents=True)
        package = directory / 'fixture.deb'
        package.write_bytes(b'owned package bytes')
        (directory / 'SHA256SUMS').write_text(hashlib.sha256(package.read_bytes()).hexdigest() +
                                            '  build/ci-packages/fixture.deb\n')
        return package

    def test_fallback_uses_bounded_authenticated_canonical_repository(self):
        result, calls = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        apt = [row for row in calls if row[0] == 'apt-get']
        self.assertEqual(len(apt), 2)
        for row in apt:
            for option in ('Acquire::http::Timeout=30', 'Acquire::https::Timeout=30',
                           'Acquire::Retries=2', 'DPkg::Lock::Timeout=60', 'Acquire::Languages=none'):
                self.assertIn(option, row)
            self.assertNotIn('--allow-unauthenticated', row)
        limits = [row for row in calls if row[0] == 'timeout']
        self.assertEqual(len(limits), 2)
        self.assertTrue(all(row[1:3] == ['--kill-after=30s', '10m'] for row in limits))
        source = Path(self.env['RUNNER_TEMP']) / 'axiom64-apt/ubuntu.sources'
        text = source.read_text()
        self.assertIn('URIs: https://archive.ubuntu.com/ubuntu', text)
        self.assertIn('Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg', text)
        self.assertIn('Suites: noble noble-updates noble-backports noble-security', text)
        self.assertTrue(all('Dir::Etc::sourcelist=' + str(source) in row for row in apt))

    def test_verified_offline_install_keeps_fast_path(self):
        self.bundle()
        result, calls = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        apt = [row for row in calls if row[0] == 'apt-get']
        self.assertEqual(len(apt), 1)
        self.assertIn('--no-download', apt[0])
        self.assertFalse(any(row[0] == 'lsb_release' for row in calls))

    def test_corrupted_package_stops_before_installation(self):
        package = self.bundle()
        package.write_bytes(b'changed package')
        result, calls = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(row[0] == 'apt-get' for row in calls))

    def test_failed_refresh_propagates_without_installation(self):
        result, calls = self.run_helper(UPDATE_STATUS='42')
        self.assertEqual(result.returncode, 42)
        self.assertFalse(any(row[0] == 'apt-get' and 'install' in row for row in calls))

    def test_failed_repository_install_propagates(self):
        result, _ = self.run_helper(INSTALL_STATUS='43')
        self.assertEqual(result.returncode, 43)

    def test_offline_miss_reuses_verified_packages(self):
        package = self.bundle()
        result, calls = self.run_helper(OFFLINE_STATUS='44')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((Path(self.env['RUNNER_TEMP']) / 'axiom64-apt' / package.name).read_bytes(), package.read_bytes())
        self.assertEqual(len([row for row in calls if row[0] == 'apt-get']), 3)

    def test_invalid_release_fails_before_repository_commands(self):
        result, calls = self.run_helper(TEST_CODENAME='noble\nTrusted: yes')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(any(row[0] == 'apt-get' for row in calls))

    def test_other_distributions_keep_configured_repositories(self):
        result, calls = self.run_helper(TEST_DISTRO='Debian', TEST_CODENAME='bookworm')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any('Dir::Etc::sourceparts=-' in row for row in calls))

    def test_prepare_uses_canonical_repository_and_retains_packages(self):
        cache = Path(self.env['RUNNER_TEMP']) / 'axiom64-apt'
        cache.mkdir(parents=True)
        package = cache / 'retained.deb'
        package.write_bytes(b'actual downloaded package fixture')
        result, calls = self.run_helper(mode='prepare')
        self.assertEqual(result.returncode, 0, result.stderr)
        apt = [row for row in calls if row[0] == 'apt-get']
        self.assertEqual(len(apt), 3)
        source = cache / 'ubuntu.sources'
        self.assertTrue(all('Dir::Etc::sourcelist=' + str(source) in row for row in apt))
        self.assertTrue(all('Dir::Etc::sourceparts=-' in row for row in apt))
        self.assertTrue(all('Acquire::Languages=none' in row for row in apt))
        self.assertIn('URIs: https://archive.ubuntu.com/ubuntu', source.read_text())
        self.assertIn('Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg', source.read_text())
        self.assertIn('qemu-system-x86', apt[1])
        self.assertIn('clang-format-20', apt[2])
        self.assertFalse(any('--allow-unauthenticated' in row for row in apt))
        limits = [row for row in calls if row[0] == 'timeout']
        self.assertEqual(len(limits), 3)
        self.assertTrue(all(row[1:3] == ['--kill-after=30s', '10m'] for row in limits))
        retained = self.root / 'build/ci-packages' / package.name
        self.assertEqual(retained.read_bytes(), package.read_bytes())
        self.assertEqual((retained.parent / 'SHA256SUMS').read_text(),
                         hashlib.sha256(package.read_bytes()).hexdigest() + '  build/ci-packages/retained.deb\n')

    def test_prepare_failed_refresh_propagates_without_installation(self):
        result, calls = self.run_helper(mode='prepare', UPDATE_STATUS='42')
        self.assertEqual(result.returncode, 42)
        self.assertFalse(any(row[0] == 'apt-get' and 'install' in row for row in calls))


if __name__ == '__main__':
    unittest.main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep package restoration bounded, authenticated and fail-closed."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import re
import shlex
import sys
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


class LocalArchiveInstall(unittest.TestCase):
    def test_complete_bundle_installs_without_repository_refresh(self):
        if os.geteuid() != 0:
            result = subprocess.run(['sudo', '-n', sys.executable, str(Path(__file__).resolve()),
                                     'LocalArchiveInstall.test_complete_bundle_installs_without_repository_refresh'],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return
        host_status = Path('/var/lib/dpkg/status')
        before = hashlib.sha256(host_status.read_bytes()).hexdigest()
        try:
            with tempfile.TemporaryDirectory(prefix='axiom64 apt local-') as temporary:
                work = Path(temporary)
                work.chmod(0o755)
                sandbox = work / 'root'
                database = sandbox / 'var/lib/dpkg'
                database.mkdir(parents=True)
                (database / 'status').write_bytes(b'')
                self.assertTrue(sandbox.resolve().is_relative_to(work.resolve()))
                bundle = work / 'build/ci-packages'
                bundle.mkdir(parents=True)
                tools = shlex.split(re.search(r'^tools=\((.*?)\)', HELPER.read_text(), re.M | re.S)[1])
                originals = {}
                for tool in tools:
                    package = work / 'packages' / tool
                    (package / 'DEBIAN').mkdir(parents=True)
                    (package / 'DEBIAN/control').write_text(
                        'Package: ' + tool + '\nVersion: 1.0\nArchitecture: all\nMaintainer: Axiom64\n'
                        'Description: Isolated CI archive acquisition fixture\n')
                    installed = package / 'usr/share/axiom64'
                    installed.mkdir(parents=True)
                    (installed / tool).write_bytes(('owned ' + tool + ' bytes\n').encode())
                    archive = bundle / (tool + '_1.0_all.deb')
                    subprocess.run(['dpkg-deb', '--build', '--root-owner-group', str(package), str(archive)],
                                   check=True, capture_output=True)
                    originals[archive.name] = hashlib.sha256(archive.read_bytes()).hexdigest()
                (bundle / 'SHA256SUMS').write_text(''.join(
                    fingerprint + '  build/ci-packages/' + name + '\n' for name, fingerprint in originals.items()))
                state = work / 'apt'
                (state / 'parts').mkdir(parents=True)
                (state / 'lists/partial').mkdir(parents=True)
                (state / 'archives/partial').mkdir(parents=True)
                (state / 'main.conf').write_text('')
                (state / 'sources.list').write_text('')
                config = state / 'apt.conf'
                values = {'Dir::Etc::main': state / 'main.conf', 'Dir::Etc::parts': state / 'parts',
                          'Dir::Etc::sourcelist': state / 'sources.list', 'Dir::Etc::sourceparts': state / 'parts',
                          'Dir::State::status': database / 'status', 'Dir::State::lists': state / 'lists',
                          'Dir::Cache::archives': state / 'archives', 'Dir::Cache::pkgcache': state / 'pkgcache',
                          'Dir::Cache::srcpkgcache': state / 'srcpkgcache', 'Dir::Log': state}
                config.write_text(''.join(name + ' "' + str(value) + '";\n' for name, value in values.items()) +
                                  'DPkg::Options:: "--root=' + str(sandbox) + '";\n')
                binaries = work / 'bin'
                binaries.mkdir()
                wrapper = """#!/usr/bin/env python3
import json,os,pathlib,subprocess,sys
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with open(os.environ['TOOL_CALLS'],'a') as output:output.write(json.dumps([name,*args])+'\\n')
if name=='sudo':
 assert args[0]=='-n'
 sys.exit(subprocess.call(args[1:]))
if name=='apt-get':os.execv('/usr/bin/apt-get',['apt-get',*args])
if name=='dpkg-query':os.execv('/usr/bin/dpkg-query',['dpkg-query','--admindir='+os.environ['FIXTURE_DPKG'],*args])
if name=='lsb_release':print('Fixture' if '-is' in args else 'noble')
"""
                for name in ('sudo', 'apt-get', 'dpkg-query', 'lsb_release'):
                    executable = binaries / name
                    executable.write_text(wrapper)
                    executable.chmod(0o755)
                calls = work / 'calls.jsonl'
                environment = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'],
                                   APT_CONFIG=str(config), RUNNER_TEMP=str(work / 'runner'),
                                   FIXTURE_DPKG=str(database), TOOL_CALLS=str(calls))
                result = subprocess.run(['bash', str(HELPER), 'restore'], cwd=work,
                                        env=environment, capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                observed = [json.loads(line) for line in calls.read_text().splitlines()]
                apt = [row for row in observed if row[0] == 'apt-get']
                self.assertEqual(len(apt), 1)
                self.assertIn('--no-download', apt[0])
                self.assertIn('Dir::Cache::archives=' + str(bundle), apt[0])
                self.assertFalse(any(row[0] == 'lsb_release' for row in observed))
                for tool in tools:
                    self.assertEqual((sandbox / 'usr/share/axiom64' / tool).read_bytes(),
                                     ('owned ' + tool + ' bytes\n').encode())
                self.assertEqual({name: hashlib.sha256((bundle / name).read_bytes()).hexdigest()
                                  for name in originals}, originals)
        finally:
            self.assertEqual(hashlib.sha256(host_status.read_bytes()).hexdigest(), before)


if __name__ == '__main__':
    unittest.main()

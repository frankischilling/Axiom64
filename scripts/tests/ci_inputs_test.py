# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise archive privacy, profile boundaries and preserved build metadata."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[2] / 'scripts/ci/inputs.sh'
BUSYBOX = 'build/busybox-1.37.0/'


class InputArchives(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom64-ci-inputs-')
        self.addCleanup(self.temporary.cleanup)
        parent = Path(self.temporary.name)
        self.workspace = parent / 'workspace with spaces'
        self.output = parent / 'exports with spaces'
        self.workspace.mkdir()
        self.output.mkdir()
        self.env = dict(os.environ, RUNNER_TEMP=str(self.output))
        self.files = {
            'dependencies.json': json.dumps({'busybox': {'version': '1.37.0'},
                'openssl': {'archive': 'openssl-locked.tar.gz'},
                'curl': {'archive': 'curl-locked.tar.xz'}}).encode(),
            'ports.lock.json': json.dumps({'packages': [
                {'name': 'linux-headers', 'archive': 'linux-headers-locked.apk'}]}).encode(),
            'downloads/ports/linux-headers-locked.apk': b'pinned Linux UAPI',
            'build/gnu-reader-controls-extra/result.json': b'keep reader prefix collision',
            'build/gnu-reader-public-controls-extra/result.json': b'keep public prefix collision',
            'build/ext2-xattr-codec-extra/result.json': b'keep codec prefix collision',
            'downloads/openssl-other.tar.gz': b'keep unrelated archive',
            'userspace/source.c': b'int main(void) { return 0; }\n',
            'scripts/check.py': b'pass\n',
            'docs/build.md': b'Build instructions.\n',
            'build/axiom64.elf': b'prepared kernel',
            'build/init': b'prepared init',
            'build/musl/runtime/id/manifest.json': b'{}\n',
            'build/musl/runtime/id/libc.so': b'prepared libc',
            'downloads/package.tar.gz': b'locked download',
            'build/curl/build/id/stage/curl': b'unrelated curl build',
            'build/openssl/runtime/id/stage/ssl': b'unrelated openssl build',
            'build/rootfs.cpio': b'complete root',
            'build/rootfs-desktop.cpio': b'desktop root',
            'build/curl-extra/result.json': b'keep prefix collision',
            'build/openssl-check/result.json': b'keep prefix collision',
            BUSYBOX + 'busybox': b'prepared busybox',
            BUSYBOX + '.config': b'prepared configuration',
            BUSYBOX + 'LICENSE': b'required license',
            BUSYBOX + '.axiom64-toolchain': b'pinned provider',
            BUSYBOX + 'unused.o': b'excluded object',
            '.git/config': b'private git metadata',
            '.local/answers.md': b'private decisions',
            'scripts/__pycache__/check.pyc': b'bytecode cache',
            'downloads/sources/project/source.c': b'expanded download',
            'build/axiom64-sources.tar': b'already exported sources',
            'build/axiom64.iso': b'already exported image',
            'build/iso-staging/root.cpio': b'duplicate staging',
            'build/uapi/linux/header.h': b'generated headers',
            'build/openssl/source/source.c': b'expanded openssl source',
            'build/openssl/build/id/static/build/test/program': b'unused upstream test',
            'build/openssl/build/id/static/build/fuzz/program': b'unused upstream fuzz',
            'build/openssl/build/id/static/build/unit.o': b'unused upstream object',
            'build/openssl/build/id/static/build/unit.a': b'unused upstream archive',
        }
        self.rotation_excluded = {
            'build/gnu-reader-controls/moved-kit/libc.a': b'completed reader control',
            'build/gnu-reader-public-controls/moved-kit/libc.a': b'completed public control',
            'build/ext2-xattr-codec/seed-1024.img': b'completed codec fixture',
            'downloads/ports/gcc-locked.apk': b'guest compiler package',
            'downloads/ports/mesa-locked.apk': b'desktop package',
            'downloads/openssl-locked.tar.gz': b'unrelated OpenSSL source',
            'downloads/curl-locked.tar.xz': b'unrelated curl source',
        }
        self.files.update(self.rotation_excluded)
        for name, data in self.files.items():
            path = self.workspace / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o751)
            os.utime(path, (1577836800, 1577836800))
        (self.workspace / 'build/musl/runtime/id/loader').symlink_to('libc.so')

    def run_helper(self, profile, env=None):
        return subprocess.run(['bash', str(HELPER), profile], cwd=self.workspace,
                              env=env or self.env, capture_output=True, text=True)

    def read(self, profile):
        name = 'ci-inputs.tar.gz' if profile == 'full' else 'ci-rotation-inputs.tar.gz'
        with tarfile.open(self.output / name) as archive:
            members = {member.name.removeprefix('./'): member for member in archive.getmembers()}
            files = {name: archive.extractfile(member).read()
                     for name, member in members.items() if member.isfile()}
        return members, files

    def test_profiles_preserve_inputs_and_metadata(self):
        for profile in ('full', 'rotation'):
            result = self.run_helper(profile)
            self.assertEqual(result.returncode, 0, result.stderr)
        full_members, full = self.read('full')
        rotation_members, rotation = self.read('rotation')
        removed = {'build/curl/build/id/stage/curl', 'build/openssl/runtime/id/stage/ssl',
                   'build/rootfs.cpio', 'build/rootfs-desktop.cpio', *self.rotation_excluded}
        self.assertEqual(set(full) - set(rotation), removed)
        self.assertFalse(set(rotation) - set(full))
        for name in rotation:
            self.assertEqual(rotation[name], self.files[name])
            self.assertEqual(full[name], rotation[name])
            self.assertEqual(rotation_members[name].mode, 0o751)
            self.assertEqual(rotation_members[name].mtime, 1577836800)
        for name in ('userspace/source.c', 'build/axiom64.elf', 'build/init',
                     'build/musl/runtime/id/libc.so', 'downloads/package.tar.gz',
                     'build/curl-extra/result.json', 'build/openssl-check/result.json'):
            self.assertIn(name, rotation)
        self.assertEqual(rotation_members['build/musl/runtime/id/loader'].linkname, 'libc.so')
        self.assertEqual(full_members['build/musl/runtime/id/loader'].linkname, 'libc.so')

    def test_rotation_omits_completed_controls_and_unrelated_downloads(self):
        self.assertEqual(self.run_helper('rotation').returncode, 0)
        members, actual = self.read('rotation')
        self.assertFalse(set(actual) & set(self.rotation_excluded))
        for name in ('downloads/ports/linux-headers-locked.apk',
                     'build/gnu-reader-controls-extra/result.json',
                     'build/gnu-reader-public-controls-extra/result.json',
                     'build/ext2-xattr-codec-extra/result.json',
                     'downloads/openssl-other.tar.gz'):
            self.assertEqual(actual[name], self.files[name])
            self.assertEqual(members[name].mode, 0o751)
            self.assertEqual(members[name].mtime, 1577836800)

    def test_rotation_materializes_required_hard_link_from_excluded_control(self):
        control = self.workspace / 'build/gnu-reader-controls/moved-kit/libc.a'
        kept = self.workspace / 'build/gnu-utmp-reader/libc.a'
        kept.parent.mkdir()
        os.link(control, kept)
        self.assertEqual(self.run_helper('rotation').returncode, 0)
        members, actual = self.read('rotation')
        self.assertNotIn('build/gnu-reader-controls/moved-kit/libc.a', members)
        self.assertEqual(actual['build/gnu-utmp-reader/libc.a'], control.read_bytes())
        self.assertTrue(members['build/gnu-utmp-reader/libc.a'].isfile())
        self.assertEqual(members['build/gnu-utmp-reader/libc.a'].mode, 0o751)
        self.assertEqual(members['build/gnu-utmp-reader/libc.a'].mtime, 1577836800)

    def test_rotation_requires_the_pinned_uapi_archive(self):
        (self.workspace / 'downloads/ports/linux-headers-locked.apk').unlink()
        result = self.run_helper('rotation')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('linux-headers-locked.apk', result.stderr)
        self.assertFalse((self.output / 'ci-rotation-inputs.tar.gz').exists())

    def test_common_privacy_and_cache_exclusions(self):
        excluded = set(self.files) - {
            'dependencies.json', 'ports.lock.json', 'userspace/source.c', 'scripts/check.py', 'docs/build.md',
            'downloads/ports/linux-headers-locked.apk', 'downloads/openssl-other.tar.gz',
            'build/gnu-reader-controls-extra/result.json',
            'build/gnu-reader-public-controls-extra/result.json',
            'build/ext2-xattr-codec-extra/result.json', *self.rotation_excluded,
            'build/axiom64.elf', 'build/init', 'build/musl/runtime/id/manifest.json',
            'build/musl/runtime/id/libc.so', 'downloads/package.tar.gz',
            'build/curl/build/id/stage/curl', 'build/openssl/runtime/id/stage/ssl',
            'build/rootfs.cpio', 'build/rootfs-desktop.cpio',
            'build/curl-extra/result.json', 'build/openssl-check/result.json',
            *(BUSYBOX + name for name in ('busybox', '.config', 'LICENSE', '.axiom64-toolchain'))}
        self.assertEqual(self.run_helper('full').returncode, 0)
        _, actual = self.read('full')
        self.assertEqual(set(actual), set(self.files) - excluded)
        for name in excluded:
            self.assertNotIn(name, actual)

    def test_reject_unknown_profile_and_existing_archive(self):
        self.assertEqual(self.run_helper('unknown').returncode, 2)
        self.assertFalse(list(self.output.iterdir()))
        self.assertEqual(self.run_helper('full').returncode, 0)
        path = self.output / 'ci-inputs.tar.gz'
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(self.run_helper('full').returncode, 2)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_reject_output_inside_workspace(self):
        inside = self.workspace / 'nested exports'
        inside.mkdir()
        result = self.run_helper('full', dict(self.env, RUNNER_TEMP=str(inside)))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(list(inside.iterdir()))


if __name__ == '__main__':
    unittest.main()

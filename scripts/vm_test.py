#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check persistent VM creation, exclusive ownership, rejection and real account reboots."""
import argparse
import fcntl
import json
from pathlib import Path
import subprocess

from account_normal_test import boot, build_observer, image, inspect, save
from build_accounts import digest
from fetch import ROOT


def prepare(directory, state, label, expected_status=0):
    command = ['python3', 'scripts/vm.py', '--prepare-only', '--state-directory', str(state)]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    (directory / (label + '.log')).write_text(result.stdout + result.stderr)
    assert result.returncode == expected_status, result.stderr
    return json.loads(result.stdout) if expected_status == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/vm-state-test')
    args = parser.parse_args()
    directory = args.directory.resolve()
    assert directory.is_relative_to((ROOT / 'build').resolve())
    directory.mkdir(parents=True, exist_ok=False)
    subprocess.run(['make', '-s', '-j2', 'build/rootfs.cpio', 'build/axiom64.elf'], cwd=ROOT, check=True)
    paths = [path for parent in ('kernel', 'userspace', 'scripts') for path in (ROOT / parent).rglob('*')
             if path.is_file() and path.suffix in ('.cpp', '.hpp', '.asm', '.c', '.h', '.sh', '.py')]
    paths += [ROOT / name for name in ('Makefile', 'sources.lock.json', 'ports.lock.json',
                                     'dependencies.json', 'boot/limine.conf')]
    source = {path.relative_to(ROOT).as_posix(): digest(path) for path in paths}
    save(directory / 'source-inputs.json', source)
    state = directory / 'state'
    created = prepare(directory, state, 'first-create')
    disk = Path(created['disk'])
    assert created['created'] and disk == state / 'root.ext2'
    manifest = state / 'created.json'
    manifest_hash = digest(manifest)
    metadata = json.loads(manifest.read_text())
    assert metadata['initial_rootfs_sha256'] == digest(ROOT / 'build/rootfs.cpio')
    assert metadata['initial_disk_sha256'] == digest(disk)
    before = digest(disk)
    reused = prepare(directory, state, 'reuse-before-login')
    assert not reused['created'] and digest(disk) == before and digest(manifest) == manifest_hash
    with (state / 'lock').open('r+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        prepare(directory, state, 'concurrent-denial', 1)
        assert digest(disk) == before
    negatives = []
    for name in ('missing-manifest', 'bad-manifest', 'symlink-disk', 'pending-create'):
        case = directory / name
        case.mkdir()
        target = case / 'root.ext2'
        if name == 'symlink-disk':
            target.symlink_to(disk)
            (case / 'created.json').write_text(manifest.read_text())
        elif name == 'pending-create':
            (case / 'pending-fixture.ext2').write_bytes(b'retain interrupted creation\n')
        else:
            target.write_bytes(b'retain existing disk\n')
            if name == 'bad-manifest':
                (case / 'created.json').write_text('{"version":0,"disk":"root.ext2"}\n')
        contents = {path.name: digest(path) for path in case.iterdir() if not path.is_symlink()}
        prepare(directory, case, name, 1)
        assert all(digest(case / path) == value for path, value in contents.items())
        if name == 'symlink-disk':
            assert target.is_symlink() and target.readlink() == disk and digest(disk) == before
        negatives.append(name)
    program, compiler = build_observer(directory)
    # Add only an observation client. Accounts and passwords are created by the
    # actual normal guest, using the unmodified production services and full image.
    command = '\n'.join((f'write {program} /usr/bin/account-normal-observe',
                         'set_inode_field /usr/bin/account-normal-observe mode 0100755',
                         'set_inode_field /usr/bin/account-normal-observe uid 0',
                         'set_inode_field /usr/bin/account-normal-observe gid 0')) + '\n'
    subprocess.run(['debugfs', '-w', '-f', '-', str(disk)], input=command, text=True,
                   check=True, capture_output=True)
    iso = image(directory, None, disk_root=True)
    inputs = dict(observer=compiler, initial_manifest_sha256=manifest_hash,
                  normal_cpio_sha256=digest(ROOT / 'build/rootfs.cpio'),
                  kernel_sha256=digest(ROOT / 'build/axiom64.elf'), image_sha256=digest(iso))
    save(directory / 'inputs.json', inputs)
    rows, prior = [], None
    for fresh in (True, False):
        phase = 'create' if fresh else 'reboot'
        with (state / 'lock').open('r+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            row = boot(directory, phase, iso, 'bios', fresh, disk, 'modern')
        rows.append(row)
        save(directory / 'results.json', rows)
        assert row['passed'], row
        row['host_state'] = inspect(disk, directory, phase)
        changed = digest(disk)
        reused = prepare(directory, state, 'reuse-after-' + phase)
        assert not reused['created'] and digest(disk) == changed and digest(manifest) == manifest_hash
        if prior:
            current = row['host_state']['current']
            assert prior['current'] == current
            stable = ['/home/admin', '/home/admin/persisted-account', '/etc/axiom64/accounts/current']
            stable += ['/etc/axiom64/accounts/' + current + '/' + name for name in ('passwd', 'group', 'shadow')]
            assert all(prior['files'][name] == row['host_state']['files'][name] for name in stable)
        prior = row['host_state']
        save(directory / 'results.json', rows)
    save(directory / 'state-results.json', dict(created=created, controls=negatives,
        concurrent_denial=True, manifest_sha256=manifest_hash, passed=True))
    assert source == {name: digest(ROOT / name) for name in source}
    print('VM_STATE_TEST_PASS exclusive_owner=1 rejection_controls=4 normal_full_boots=2 host_fsck=2', flush=True)


if __name__ == '__main__':
    main()

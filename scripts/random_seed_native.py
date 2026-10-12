#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare seed rotation and unsafe-state recovery with native Linux filesystems."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import tempfile

from build_musl import compiler_args, loader
from build_openssl import native_inputs
from fetch import ROOT
from random_administration_test import fingerprint, snapshot


def evidence(path):
    status = path.lstat()
    value = dict(mode=stat.S_IMODE(status.st_mode), uid=status.st_uid, gid=status.st_gid,
                 links=status.st_nlink, size=status.st_size)
    if stat.S_ISREG(status.st_mode):
        value['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    if path.is_symlink():
        value['symlink'] = os.readlink(path)
    return value


def cases(output, client, linkage):
    rows = []
    with tempfile.TemporaryDirectory(prefix='axiom64-random-seed-native-') as name:
        jail = Path(name)
        for directory in ('bin', 'lib', 'dev', 'var', 'var/lib', 'var/lib/axiom64'):
            (jail / directory).mkdir(mode=0o755)
        shutil.copyfile(client, jail / 'bin/random-seed')
        (jail / 'bin/random-seed').chmod(0o755)
        if linkage == 'dynamic':
            shutil.copyfile(loader(), jail / 'lib/ld-musl-x86_64.so.1')
            (jail / 'lib/ld-musl-x86_64.so.1').chmod(0o755)
        os.mknod(jail / 'dev/urandom', stat.S_IFCHR | 0o666, os.makedev(1, 9))
        folder = jail / 'var/lib/axiom64/random'
        seed = folder / 'seed'

        def run(label, mode='load', error=0):
            result = subprocess.run(['chroot', str(jail), '/bin/random-seed', mode],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
            log = output / (label + '.log')
            log.write_bytes(result.stdout)
            text = result.stdout.decode()
            passed = result.returncode == int(bool(error)) and (
                ('RANDOM_SEED_FAILED ' in text and f'error={error}\n' in text) if error else
                (f'RANDOM_SEED_PASS mode={mode} ' in text and 'credited_bits=0' in text))
            row = dict(case=label, mode=mode, returncode=result.returncode, expected_error=error,
                       log=log.name, log_input=fingerprint(log), passed=passed)
            if seed.exists() or seed.is_symlink():
                row['seed'] = evidence(seed)
            rows.append(row)
            (output / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            if not passed:
                raise RuntimeError('native seed service failed: ' + linkage + '/' + label)
            print('NATIVE_SEED_CASE_PASS linkage=' + linkage + ' case=' + label, flush=True)

        run('first-rotation', 'boot')
        first = seed.read_bytes()
        metadata = evidence(seed)
        assert metadata['mode'] == 0o600 and metadata['links'] == 1 and len(first) == 32
        run('uncredited-load')
        assert seed.read_bytes() == first
        run('second-rotation', 'boot')
        assert len(seed.read_bytes()) == 32 and seed.read_bytes() != first
        original = bytes(range(32))

        def reset():
            for path in folder.iterdir():
                if path.name != 'lock':
                    path.unlink()
            seed.write_bytes(original)
            seed.chmod(0o600)
            os.chown(seed, 0, 0)

        reset()
        seed.chmod(0o644)
        before = evidence(seed)
        run('permissive-file-rejected', error=1)
        assert evidence(seed) == before
        reset()
        os.chown(seed, 1000, 1000)
        before = evidence(seed)
        run('untrusted-owner-rejected', error=1)
        assert evidence(seed) == before
        reset()
        os.link(seed, folder / 'unknown-link')
        before = evidence(seed)
        run('unknown-hardlink-rejected', error=1)
        assert evidence(seed) == before
        reset()
        seed.write_bytes(original[:-1])
        before = evidence(seed)
        run('short-seed-rejected', error=22)
        assert evidence(seed) == before
        reset()
        seed.unlink()
        seed.symlink_to('lock')
        before = evidence(seed)
        run('symlink-rejected', error=40)
        assert evidence(seed) == before
        reset()
        seed.unlink()
        os.mkfifo(seed, 0o600)
        before = evidence(seed)
        run('fifo-rejected-without-blocking', error=1)
        assert evidence(seed) == before
        reset()
        folder.chmod(0o755)
        before = evidence(seed)
        run('nonprivate-directory-rejected', error=1)
        assert evidence(seed) == before
        folder.chmod(0o700)
        reset()
        os.link(seed, folder / 'seed.previous')
        run('interrupted-checkpoint-recovery')
        assert seed.read_bytes() == original and seed.stat().st_nlink == 1
        assert not (folder / 'seed.previous').exists()
        reset()
        seed.rename(folder / 'seed.previous')
        run('missing-current-seed-recovery')
        assert seed.read_bytes() == original and seed.stat().st_nlink == 1
        reset()
        previous = folder / 'seed.previous'
        previous.write_bytes(b'previous seed generation payload')
        previous.chmod(0o600)
        run('replacement-already-complete-recovery')
        assert seed.read_bytes() == original and not previous.exists()
        reset()
        temporary = folder / 'seed.tmp.1234.0'
        temporary.write_bytes(b'incomplete')
        temporary.chmod(0o600)
        sentinel = folder / 'keep-this-unrelated-file'
        sentinel.write_bytes(b'keep')
        run('orphan-temporary-recovery')
        assert not temporary.exists() and sentinel.read_bytes() == b'keep'
        reset()
        temporary.write_bytes(b'incomplete')
        temporary.chmod(0o644)
        before = evidence(temporary)
        run('unsafe-orphan-rejected', error=1)
        assert evidence(temporary) == before
        reset()
        with (folder / 'lock').open('rb') as owner:
            fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run('second-singleton-owner-rejected', error=11)
        run('rotation-after-rejections', 'boot')
    return rows


def publication_cases(output, client, linkage):
    rows = []
    for mode in ('before', 'after'):
        with tempfile.TemporaryDirectory(prefix='axiom64-seed-publication-native-') as name:
            jail = Path(name)
            for directory in ('bin', 'lib', 'dev', 'var', 'var/lib', 'var/lib/axiom64'):
                (jail / directory).mkdir(mode=0o755)
            shutil.copyfile(client, jail / 'bin/random-seed')
            (jail / 'bin/random-seed').chmod(0o755)
            if linkage == 'dynamic':
                shutil.copyfile(loader(), jail / 'lib/ld-musl-x86_64.so.1')
                (jail / 'lib/ld-musl-x86_64.so.1').chmod(0o755)
            os.mknod(jail / 'dev/urandom', stat.S_IFCHR | 0o666, os.makedev(1, 9))
            folder = jail / 'var/lib/axiom64/random'
            folder.mkdir(mode=0o700)
            seed = folder / 'seed'
            original = bytes(range(32))
            seed.write_bytes(original)
            seed.chmod(0o600)
            inode = seed.stat().st_ino
            before = evidence(seed)
            command = ['chroot', str(jail), '/bin/random-seed', 'rotate']
            result = subprocess.run(command, env=dict(os.environ, AXIOM64_SEED_RENAME_ERROR=mode),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
            log = output / ('publication-' + mode + '.log')
            log.write_bytes(result.stdout)
            text = result.stdout.decode()
            marker = 'NATIVE_SEED_RENAME_ERROR phase=' + mode + (
                ' kernel_called=1 kernel_result=0' if mode == 'after' else ' kernel_called=0')
            row = dict(case='publication-' + mode, returncode=result.returncode,
                       failure_fixture='reported EIO ' + mode + ' a native rename, not a disk fault',
                       before=before, after=evidence(seed), original_inode=inode,
                       log=log.name, log_input=fingerprint(log), passed=False)
            try:
                assert result.returncode == 1 and marker in text
                assert 'RANDOM_SEED_FAILED stage=atomic-publication error=5' in text
                assert seed.read_bytes() == original and seed.stat().st_ino == inode
                assert evidence(seed) == before
                assert {path.name for path in folder.iterdir()} == {'seed', 'lock'}
                retry = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       env={key: value for key, value in os.environ.items()
                                            if key != 'AXIOM64_SEED_RENAME_ERROR'}, timeout=10)
                retry_log = output / ('publication-' + mode + '-retry.log')
                retry_log.write_bytes(retry.stdout)
                assert retry.returncode == 0 and b'RANDOM_SEED_PASS mode=rotate ' in retry.stdout
                assert len(seed.read_bytes()) == 32 and seed.read_bytes() != original
                assert seed.stat().st_nlink == 1
                assert {path.name for path in folder.iterdir()} == {'seed', 'lock'}
                row.update(passed=True, retry=dict(returncode=retry.returncode,
                           log=retry_log.name, log_input=fingerprint(retry_log)), final=evidence(seed))
            finally:
                (output / ('publication-' + mode + '-result.json')).write_text(
                    json.dumps(row, indent=2) + '\n')
            rows.append(row)
            print('NATIVE_SEED_CASE_PASS linkage=' + linkage + ' case=publication-' + mode, flush=True)
    return rows


def compile_client(output, linkage, sources, fault=False, wraps=()):
    output.mkdir()
    compiler = ['gcc'] if linkage == 'native' else compiler_args()
    flags = ['-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror']
    client = output / 'random-seed'
    command = [*compiler, *flags, *(['-static'] if linkage != 'dynamic' else []),
               *(str(source) for source in sources), *(['-Wl,--wrap=renameat'] if fault else []),
               *('-Wl,--wrap=' + name for name in wraps),
               '-o', str(client)]
    with (output / 'compile.log').open('wb') as stream:
        subprocess.run(command, cwd=ROOT, check=True, stdout=stream, stderr=subprocess.STDOUT)
    headers = {}
    for source in sources:
        dependencies = subprocess.check_output([*compiler, *flags, '-M', str(source)], text=True)
        for name in shlex.split(dependencies.replace('\\\n', ' ').split(':', 1)[1]):
            path = Path(name)
            if not path.is_absolute():
                path = ROOT / path
            value = fingerprint(path)
            stored = output / 'inputs' / value['sha256'] / path.name
            stored.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, stored)
            headers[str(path)] = dict(**value, stored=str(stored.relative_to(output.parent)))
    product = dict(command=command, client=fingerprint(client), headers=headers,
                   native_inputs=native_inputs() if linkage == 'native' else {},
                   loader=fingerprint(loader()) if linkage == 'dynamic' else None,
                   fault_fixture=fault, wrapped_calls=list(wraps))
    (output / 'products.json').write_text(json.dumps(product, indent=2) + '\n')
    return client, product


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-seed-native-results')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('native seed comparisons require a root-owned isolated chroot')
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    inputs = snapshot(directory)
    for name in ('userspace/services/random_seed.c', 'userspace/tests/random/seed_publication_error.c',
                 'scripts/random_seed_native.py',
                 'scripts/build_openssl.py'):
        inputs[name] = fingerprint(ROOT / name)
    (directory / 'source-inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
    results = []
    for linkage in ('native', 'static', 'dynamic'):
        output = directory / linkage
        source = ROOT / 'userspace/services/random_seed.c'
        client, product = compile_client(output, linkage, [source])
        results += [dict(linkage=linkage, **row) for row in cases(output, client, linkage)]
        assert product['client'] == fingerprint(client)
        assert all({key: value[key] for key in ('bytes', 'sha256')} == fingerprint(Path(name))
                   for name, value in product['headers'].items())
        fault_output = directory / (linkage + '-publication')
        fault_client, fault_product = compile_client(fault_output, linkage, [
            source, ROOT / 'userspace/tests/random/seed_publication_error.c'], fault=True)
        results += [dict(linkage=linkage, **row) for row in publication_cases(
            fault_output, fault_client, linkage)]
        assert fault_product['client'] == fingerprint(fault_client)
        assert all({key: value[key] for key in ('bytes', 'sha256')} == fingerprint(Path(name))
                   for name, value in fault_product['headers'].items())
        (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    assert inputs == {name: fingerprint(ROOT / name) for name in inputs}


if __name__ == '__main__':
    main()

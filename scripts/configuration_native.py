# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare configuration ownership and recovery in a private Linux namespace."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

from configuration_inputs import PROGRAMS, digest, freeze, missing, retain, unchanged, write
from fetch import ROOT


def run(directory, profile, timeout):
    products = retain(directory, profile)
    command = ([str(directory / 'loader.elf')] if profile == 'dynamic' else []) + [str(directory / 'program.elf'), '--native']
    log = directory / 'client.log'
    runtime = {}
    maps = ''
    started = time.monotonic()
    with log.open('xb') as output:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            while process.poll() is None:
                if not maps:
                    try:
                        current = Path(f'/proc/{process.pid}/maps').read_text()
                        ready = str(directory / 'program.elf') in current
                        if profile == 'native':
                            ready = ready and 'libc.so' in current
                        if ready:
                            providers = {}
                            for line in current.splitlines():
                                fields = line.split(None, 5)
                                if len(fields) != 6 or not fields[5].startswith('/'):
                                    continue
                                path = Path(fields[5])
                                if path in (directory / 'program.elf', directory / 'loader.elf'):
                                    continue
                                if '.so' in path.name or 'ld-linux' in path.name:
                                    providers[path] = int(fields[4])
                            (directory / 'runtime').mkdir()
                            for number, (path, inode) in enumerate(providers.items()):
                                assert path.stat().st_ino == inode
                                name = 'runtime/' + str(number) + '-' + path.name
                                shutil.copy2(path, directory / name)
                                runtime[name] = dict(source=str(path), inode=inode, sha256=digest(directory / name))
                            maps = current
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                elapsed = time.monotonic() - started
                if elapsed >= timeout:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(.002)
            process.wait()
        except BaseException:
            process.kill()
            process.wait()
            raise
    (directory / 'maps.txt').write_text(maps)
    text = log.read_text(errors='replace')
    absent = missing(text, True)
    runtime_unchanged = all(digest(Path(row['source'])) == row['sha256'] for row in runtime.values())
    result = dict(profile=profile, returncode=process.returncode, missing=absent, command=command,
                  kernel=platform.uname()._asdict(), namespace_inode=os.stat('/proc/self/ns/net').st_ino,
                  pid=process.pid, log_sha256=digest(log), products=products,
                  runtime=runtime, runtime_unchanged=runtime_unchanged,
                  maps_sha256=digest(directory / 'maps.txt'), seconds=round(time.monotonic() - started, 3),
                  passed=process.returncode == 0 and not absent and bool(maps) and runtime_unchanged)
    write(directory / 'results.json', result)
    print(json.dumps({key: result[key] for key in ('profile', 'returncode', 'missing', 'passed')}), flush=True)
    if not result['passed']:
        print(text[-2500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=['native', 'static', 'dynamic', 'all'], default='all')
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/configuration-native-evidence')
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('a private network namespace requires root')
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    profiles = ['native', 'static', 'dynamic'] if args.profile == 'all' else [args.profile]
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    with (directory / 'build.log').open('xb') as output:
        subprocess.run(['make', '-j4', *['build/' + PROGRAMS[profile] for profile in profiles]], cwd=ROOT,
                       stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, check=True)
    source = freeze(directory)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    if libc.unshare(0x40000000) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    for name in ['eth0', 'eth1']:
        subprocess.run(['ip', 'link', 'add', 'name', name, 'type', 'dummy'], stdin=subprocess.DEVNULL, check=True)
    write(directory / 'native-configuration.json', {name: json.loads(subprocess.check_output(['ip', '-json', name, 'show']))
          for name in ('link', 'address', 'route')})
    receipt = dict(kind='native', source=source, requested=profiles, results=[],
                   original_timeout_seconds=args.timeout, passed=False)
    write(directory / 'acceptance.json', receipt)
    for profile in profiles:
        result = run(directory / profile, profile, args.timeout)
        receipt['results'].append(result)
        write(directory / 'acceptance.json', receipt)
        if not result['passed']:
            raise RuntimeError('Native configuration ownership/recovery comparison failed')
        temporary = Path('/tmp') / ('axiom64-network-owner-' + str(result['pid']))
        if temporary.is_dir() and not any(temporary.iterdir()):
            temporary.rmdir()
    receipt['source_unchanged'] = unchanged(directory)
    receipt['passed'] = receipt['source_unchanged'] and all(row['passed'] for row in receipt['results'])
    write(directory / 'acceptance.json', receipt)
    if not receipt['passed']:
        raise RuntimeError('Configuration source changed during native validation')


if __name__ == '__main__':
    main()

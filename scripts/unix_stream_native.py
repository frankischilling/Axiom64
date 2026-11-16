#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the stream ancillary client under three actual Linux caller identities."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from compile_uapi_client import audit_compile
from fetch import ROOT
from tcp_fixture_inputs import digest
from unix_datagram_contract import CLIENTS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/unix-stream-native')
    args = parser.parse_args()
    if os.geteuid():
        parser.error('run as root to compare root, credential drop and already-ordinary callers')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    program = directory / 'unix_stream'
    command = [sys.executable, '-B', 'scripts/compile_uapi_client.py', '--compiler', 'gcc',
               '--output', str(program), '--', '-std=c11', '-O2', '-g', '-Wall', '-Wextra',
               '-Werror', 'userspace/tests/ipc/unix_stream.c']
    subprocess.run(command, cwd=ROOT, check=True)
    compiled = audit_compile(program, ROOT)
    rows = []
    # The checkout can have private ancestors. Execute an identical public copy
    # without changing the compiled input or any existing directory permissions.
    with tempfile.TemporaryDirectory(prefix='axiom-unix-native-', dir='/var/tmp') as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o755)
        executable = scratch / 'unix_stream'
        shutil.copyfile(program, executable)
        executable.chmod(0o555)
        execution_sha256 = digest(executable)
        if execution_sha256 != compiled['product']['sha256']:
            raise ValueError('native execution copy differs from compiled program')
        for name, arguments, identity, uid in [
                ('root', [], dict(extra_groups=[]), 0),
                ('drop', ['--ordinary'], dict(extra_groups=[]), 65534),
                ('ordinary', [], dict(user=65534, group=65534, extra_groups=[]), 65534)]:
            start = time.monotonic_ns()
            process = subprocess.run([str(executable), *arguments], stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, timeout=30, **identity)
            log = directory / (name + '.log')
            log.write_bytes(process.stdout)
            lines = process.stdout.decode().splitlines()
            expected = f'UNIX_STREAM_IDENTITY uid={uid} euid={uid} gid={uid} egid={uid} groups=0'
            if (process.returncode or lines.count(expected) != 1 or
                    lines.count(f'UNIX_STREAM_PASS groups={CLIENTS["unix_stream"]}') != 1 or
                    any('_FAIL' in line for line in lines)):
                raise ValueError('native stream comparison failed: ' + name + '\n' + '\n'.join(lines))
            rows.append(dict(mode=name, uid=uid, command=[str(executable), *arguments],
                             returncode=process.returncode, elapsed_ns=time.monotonic_ns() - start,
                             log_sha256=digest(log)))
        if digest(executable) != execution_sha256:
            raise ValueError('native execution copy changed during comparison')
    if audit_compile(program, ROOT) != compiled:
        raise ValueError('native stream compilation inputs changed during execution')
    report = dict(passed=True, profiles=3, guest_acceptance=False,
                  kernel=subprocess.check_output(['uname', '-r'], text=True).strip(),
                  compilation=compiled, execution_sha256=execution_sha256, rows=rows)
    (directory / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print('UNIX_STREAM_NATIVE_PASS profiles=3')


if __name__ == '__main__':
    main()

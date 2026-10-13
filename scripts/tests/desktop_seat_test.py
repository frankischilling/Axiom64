#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise production seat recovery with real native ownership and procfs."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
INPUTS = ['userspace/tests/desktop/seat-recovery.c', 'userspace/desktop/seat.c',
          'userspace/desktop/seat.h', 'userspace/desktop/authority.c',
          'userspace/desktop/authority.h', 'userspace/accounts/protected.c',
          'userspace/accounts/protected.h', 'userspace/accounts/auth.h',
          'scripts/tests/desktop_seat_test.py']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--sanitize', action='store_true')
    arguments = parser.parse_args()
    if not arguments.inside:
        command = ['unshare', '--mount', '--net', '--pid', '--fork', '--mount-proc',
                   sys.executable, str(Path(__file__).resolve()), '--inside']
        if arguments.sanitize:
            command.append('--sanitize')
        return subprocess.run(command, check=False).returncode
    if os.geteuid() != 0:
        raise RuntimeError('seat ownership tests require the isolated root build host')
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', '/tmp'], check=True)
    import hashlib
    import json
    print(json.dumps({'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                      for name in INPUTS},
                      'proc_boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'framebuffer_adapter': 'native regular file plus ioctl dimensions',
                      'saved_pid_reuse_and_other_boot': 'simulated saved-state controls'},
                     sort_keys=True), flush=True)
    with tempfile.TemporaryDirectory(prefix='axiom64-seat-recovery-build-') as temporary:
        binary = Path(temporary) / 'seat-recovery'
        flags = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror']
        if arguments.sanitize:
            flags += ['-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        subprocess.run(['gcc', *flags, '-DDESKTOP_DIRECTORY="/tmp/axiom64-seat-recovery"',
                        str(ROOT / INPUTS[0]), str(ROOT / 'userspace/desktop/authority.c'),
                        str(ROOT / 'userspace/accounts/protected.c'), '-o', str(binary)],
                       check=True)
        return subprocess.run([str(binary)], check=False, timeout=30).returncode


if __name__ == '__main__':
    raise SystemExit(main())

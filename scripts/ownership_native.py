#!/usr/bin/env python3
"""Exercise permanent singleton lock ownership using real Linux processes."""
import json
import os
import platform
from pathlib import Path
import signal
import subprocess
import tempfile
from fetch import ROOT


def main():
    if os.geteuid() != 0:
        raise RuntimeError('run through sudo to test ordinary/root UIDs and real foreign owners')
    ordinary = int(os.environ.get('SUDO_UID', '1000'))
    if ordinary <= 0:
        raise RuntimeError('SUDO_UID must identify an ordinary user')
    binaries = [('gnu-sanitizers', 'ownership-host'), ('musl-static', 'ownership-tests'),
                ('musl-dynamic', 'ownership-dynamic')]
    subprocess.run(['make', '-j2', *['build/' + binary for _, binary in binaries]],
                   cwd=ROOT, check=True)
    reports = []
    for uid in (ordinary, 0):
        for linkage, binary in binaries:
            with tempfile.TemporaryDirectory(prefix='axiom64-ownership-') as directory:
                os.chown(directory, uid, uid)
                os.chmod(directory, 0o700)

                def identity():
                    os.setgroups([])
                    os.setgid(uid)
                    os.setuid(uid)

                command = [str(ROOT / 'build' / binary), directory, '--native']
                process = subprocess.Popen(command, cwd=ROOT, preexec_fn=identity,
                                           start_new_session=True, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, text=True,
                                           env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=1'})
                timed_out = False
                try:
                    output, _ = process.communicate(timeout=40)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    output, _ = process.communicate(timeout=10)
                log = ROOT / 'build' / f'ownership-native-{uid}-{linkage}.log'
                log.write_text(output)
                passed = not timed_out and process.returncode == 0 and \
                    'OWNERSHIP_PASS modes=private race_owners=1 fork_exec=pass killed_restart=pass' in output and \
                    'OWNERSHIP_FAIL' not in output
                report = dict(uid=uid, linkage=linkage, returncode=process.returncode,
                              timed_out=timed_out, log=log.name, kernel=platform.release(),
                              passed=passed)
                reports.append(report)
                (ROOT / 'build/ownership-native-results.json').write_text(
                    json.dumps(reports, indent=2) + '\n')
                print(json.dumps(report), flush=True)
                if not passed:
                    print(output, flush=True)
                    raise RuntimeError('singleton ownership native test failed')


if __name__ == '__main__':
    main()

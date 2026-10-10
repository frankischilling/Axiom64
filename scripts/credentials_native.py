# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the credential client with Linux in private mount namespaces."""
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
from fetch import ROOT


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo after building the credential clients; private mounts need root.')
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated':
        if sys.argv[2] not in ('native', 'static', 'dynamic'):
            raise SystemExit('Unknown credential client')
        subprocess.run(['mount', '-t', 'ramfs', 'none', '/tmp'], check=True)
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').write_text('1024\n')
        binary = str(ROOT / 'build' / f'credentials-{sys.argv[2]}')
        os.execv(binary, [binary])
    if len(sys.argv) != 1:
        raise SystemExit('Unexpected credential harness arguments')
    results = []
    phases = ('IDS', 'THREADS', 'CAPS', 'SHM', 'SIGNAL', 'NETWORK', 'DAC', 'PATH', 'UNIX', 'EXEC',
              'CAP_EXEC', 'INTERPRETER', 'MOUNT')
    for linkage in ('native', 'static', 'dynamic'):
        started = time.monotonic()
        command = ['unshare', '--mount', '--net', '--propagation', 'private',
                   sys.executable, str(Path(__file__).resolve()), '--isolated', linkage]
        timed_out = False
        process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            output, _ = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            output, _ = process.communicate()
        finally:
            if process.poll() is None or process.returncode or timed_out:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
        returncode = process.returncode
        log = ROOT / 'build' / f'credentials-linux-{linkage}.log'
        log.write_bytes(output)
        text = output.decode(errors='replace')
        print(text, end='', flush=True)
        required = [*(f'CREDENTIAL_{phase}_PASS ' for phase in phases),
                    f'CREDENTIAL_TEST_PASS linkage={linkage}']
        missing = [marker for marker in required if marker not in text]
        if text.count('CREDENTIAL_SERVICE_PASS actual_exec irreversible_drop') != (3 if linkage == 'static' else 4):
            missing.append('all actual privilege-dropped exec services')
        if text.count('CREDENTIAL_CAP_SERVICE_PASS ') != 3 or text.count('CREDENTIAL_GROUP_SERVICE_PASS ') != 2:
            missing.append('all actual ambient/bounding/setgid exec services')
        result = dict(kernel=platform.release(), linkage=linkage, returncode=returncode,
                      timed_out=timed_out, missing=missing, log=log.name,
                      seconds=round(time.monotonic() - started, 3),
                      passed=returncode == 0 and not timed_out and not missing and
                      'CREDENTIAL_TEST_FAIL ' not in text)
        results.append(result)
        (ROOT / 'build/credentials-linux-results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if not result['passed']:
            raise SystemExit('Native Linux credential comparison failed')


if __name__ == '__main__':
    main()

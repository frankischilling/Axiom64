# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the common TCP socket contract with native glibc and both musl linkages."""
import json
import subprocess
from fetch import ROOT


def main():
    profiles = ('native', 'static', 'dynamic')
    subprocess.run(['make', '-s', '-j2', *(f'build/tcp-{profile}' for profile in profiles)],
                   cwd=ROOT, check=True)
    required = ('TCP_CREATE_PASS variants=8', 'TCP_BINDINGS_PASS ', 'TCP_OPTIONS_PASS ', 'TCP_REFUSED_PASS ',
                'TCP_VECTORS_PASS ', 'TCP_CLIENT_PASS ', 'TCP_LOOPBACK_PASS bytes=262144', 'TCP_TEST_PASS')
    results = []
    with (ROOT / 'build/tcp-native.log').open('w') as log:
        for profile in profiles:
            process = subprocess.run([ROOT / 'build' / f'tcp-{profile}'], cwd=ROOT,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, timeout=75)
            log.write(f'PROFILE {profile}\n{process.stdout}')
            print(f'PROFILE {profile}\n{process.stdout}', end='', flush=True)
            missing = [marker for marker in required if marker not in process.stdout]
            result = dict(profile=profile, returncode=process.returncode, missing=missing,
                          passed=process.returncode == 0 and not missing and
                          'TCP_TEST_FAIL ' not in process.stdout)
            results.append(result)
            (ROOT / 'build/tcp-native-results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not result['passed']:
                raise SystemExit('Native TCP contract failed')
    print('TCP_NATIVE_MATRIX_PASS profiles=3', flush=True)


if __name__ == '__main__':
    main()

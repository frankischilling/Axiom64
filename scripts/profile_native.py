"""Check private saved-file contracts on native Linux as root and an ordinary UID."""
import argparse
import json
import os
import platform
import pwd
import subprocess
import tempfile
import time
from pathlib import Path
from fetch import ROOT

MARKERS = ['PROFILE_PRIVACY_FILES_PASS', 'PROFILE_PRIVACY_ANCESTORS_UMASK_PASS',
           'PROFILE_PRIVACY_FAILURES_PASS',
           'PROFILE_PRIVACY_NATIVE_TYPES_OWNERS_PASS', 'PROFILE_PRIVACY_TESTS_PASS']
PROFILE = b'axiom64-network=1\nmode=dhcp\n'
HINT = b'axiom64-lease=1\nmac=52:54:00:12:34:10\naddress=10.23.1.40\n'


def fixtures(root, uid, gid):
    os.chown(root, uid, gid)
    for name in ['foreign-directory', 'foreign-ancestor', 'foreign-ancestor/private', 'foreign-file']:
        path = root / name
        path.mkdir(mode=0o700)
        os.chown(path, uid, gid)
    for name in ['foreign-directory', 'foreign-ancestor/private', 'foreign-file']:
        for suffix, text in [('conf', PROFILE), ('lease', HINT)]:
            path = root / name / ('eth0.' + suffix)
            path.write_bytes(text)
            path.chmod(0o600)
            os.chown(path, 65534 if name == 'foreign-file' else uid, gid)
    for name in ['foreign-directory', 'foreign-ancestor']:
        os.chown(root / name, 65534, gid)


def run(program, uid, gid, timeout):
    label = f'profile-native-{program}-uid{uid}'
    log = ROOT / 'build' / (label + '.log')

    def credentials():
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

    started = time.monotonic()
    timed_out = False
    with tempfile.TemporaryDirectory(prefix='axiom64-profile-native-') as temporary:
        root = Path(temporary)
        fixtures(root, uid, gid)
        with log.open('wb') as output:
            process = subprocess.Popen([str(ROOT / 'build' / program), '--native', str(root)],
                                       cwd='/tmp', stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, preexec_fn=credentials)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
    text = log.read_text(errors='replace')
    missing = [marker for marker in MARKERS if marker not in text]
    result = dict(program=program, uid=uid, kernel=platform.release(), log=log.name,
                  returncode=process.returncode, timed_out=timed_out, missing=missing,
                  seconds=round(time.monotonic() - started, 3),
                  passed=not timed_out and process.returncode == 0 and not missing and
                  'ERROR: AddressSanitizer' not in text and 'runtime error:' not in text)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-3500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', type=int, default=int(os.environ.get('SUDO_UID', '1000')))
    parser.add_argument('--timeout', type=float, default=15)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root to prepare real foreign owners and drop to an ordinary UID')
    if args.uid <= 0 or args.uid == 65534 or args.timeout <= 0:
        parser.error('choose an ordinary positive UID other than the foreign fixture owner')
    account = pwd.getpwuid(args.uid)
    results = []
    for uid, gid in [(args.uid, account.pw_gid), (0, 0)]:
        for program in ['profile-privacy-host', 'profile-privacy-tests', 'profile-privacy-dynamic']:
            result = run(program, uid, gid, args.timeout)
            results.append(result)
            (ROOT / 'build/profile-native-results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not result['passed']:
                raise SystemExit('Native private saved-file contracts failed')


if __name__ == '__main__':
    main()

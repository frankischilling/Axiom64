# SPDX-License-Identifier: GPL-3.0-or-later
"""Check campaign control with real child processes, without claiming OS coverage."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ipv6_expiry_test as campaign


WORKER = '''import argparse, json, pathlib, subprocess, sys, time
parser = argparse.ArgumentParser()
parser.add_argument('--suite')
parser.add_argument('--workers')
parser.add_argument('--output-directory', type=pathlib.Path)
args = parser.parse_args()
root = pathlib.Path.cwd()
mode = (root / 'mode').read_text()
kind = 'native' if 'native' in pathlib.Path(sys.argv[0]).stem else 'guest'
(root / (kind + '.ready')).write_text('ready')
other = 'guest' if kind == 'native' else 'native'
end = time.monotonic() + 5
while not (root / (other + '.ready')).is_file():
    assert time.monotonic() < end, 'independent drivers must overlap'
    time.sleep(.01)
args.output_directory.mkdir(parents=True, exist_ok=False)
if kind == 'native':
    rows = [dict(profile=p, returncode=0) for p in ('native','static','dynamic')]
    if mode == 'missing-native': rows.pop()
    filename = 'receipt.json'
else:
    rows = [dict(linkage=l, firmware=f, transport=t, passed=True)
            for l in ('static','dynamic') for f in ('bios','uefi') for t in ('modern','legacy')]
    if mode == 'failed-guest': rows[0]['passed'] = False
    filename = 'results.json'
(args.output_directory / filename).write_text(json.dumps(rows))
if kind == 'native' and mode == 'failed-driver':
    source = "import pathlib,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); pathlib.Path('descendant.ready').write_text('ready'); time.sleep(2); pathlib.Path('descendant.leaked').write_text('leaked')"
    subprocess.Popen([sys.executable, '-c', source])
    end = time.monotonic() + 5
    while not (root / 'descendant.ready').is_file():
        assert time.monotonic() < end
        time.sleep(.01)
    sys.exit(7)
print('controller fixture complete', flush=True)
'''


class Controller(unittest.TestCase):
    def run_mode(self, mode):
        with tempfile.TemporaryDirectory(prefix='axiom64-expiry-controller-') as temporary:
            root = Path(temporary)
            sources = ('Makefile', 'userspace/tests/net/ipv6_expiry.c', 'userspace/tests/net/ipv6_fixture.h',
                       'scripts/ipv6_expiry_test.py', 'scripts/ipv6_expiry_peer.py',
                       'scripts/ipv6_expiry_capture.py', 'scripts/ipv6_host_native.py',
                       'scripts/ipv6_host_test.py', 'scripts/tcp_capture_clock.py')
            for name in sources:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(WORKER if name in ('scripts/ipv6_host_native.py', 'scripts/ipv6_host_test.py') else 'controller fixture\n')
            (root / 'mode').write_text(mode)
            output = root / 'build/evidence'
            with patch.object(campaign, 'ROOT', root), patch.object(campaign.subprocess, 'run') as build, \
                    patch.object(sys, 'argv', ['ipv6_expiry_test.py', '--output-directory', str(output)]):
                status = campaign.main()
            build.assert_called_once()
            receipt = json.loads((output / 'result.json').read_text())
            self.assertEqual((status, receipt['passed']), (0, True) if mode == 'complete' else (1, False))
            self.assertTrue(receipt['sources_unchanged'])
            for kind in ('native', 'guest'):
                self.assertTrue((output / (kind + '.log')).is_file())
                self.assertTrue((root / (kind + '.ready')).is_file())
            if mode == 'failed-driver':
                self.assertEqual(receipt['results']['native']['returncode'], 7)
                time.sleep(2.1)
                self.assertFalse((root / 'descendant.leaked').exists(), 'failed parent must not leave an owned descendant')

    def test_complete_profiles_overlap(self):
        self.run_mode('complete')

    def test_missing_native_profile_fails(self):
        self.run_mode('missing-native')

    def test_guest_failure_fails(self):
        self.run_mode('failed-guest')

    def test_failed_driver_retains_evidence_and_reaps_descendant(self):
        self.run_mode('failed-driver')


if __name__ == '__main__':
    unittest.main()

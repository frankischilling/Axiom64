# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual worker concurrency, isolated fixtures and failure evidence."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'ci' / 'paired_network.py'
SPEC = importlib.util.spec_from_file_location('paired_network', SCRIPT)
PAIRED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAIRED)

WORKER = '''import argparse, json, pathlib, subprocess, sys, time
parser = argparse.ArgumentParser()
parser.add_argument('--firmware')
parser.add_argument('--transport')
parser.add_argument('--affected')
parser.add_argument('--linkage')
args = parser.parse_args()
root = pathlib.Path.cwd()
settings = json.loads((root / 'settings.json').read_text())
barrier = pathlib.Path(settings['barrier'])
build = root / 'build'
build.mkdir(exist_ok=True)
(build / 'fixture').write_text(args.linkage)
(barrier / args.linkage).write_text('ready')
deadline = time.monotonic() + 10
other = 'dynamic' if args.linkage == 'static' else 'static'
while not (barrier / other).exists():
    if time.monotonic() > deadline:
        raise RuntimeError('both workers must run at once')
    time.sleep(0.02)
assert (build / 'fixture').read_text() == args.linkage
assert (args.firmware, args.transport, args.affected) == ('bios', 'modern', '0')
(build / 'manager-protocol-results.json').write_text(json.dumps(vars(args)))
(build / 'manager-protocol-packets.json').write_text(json.dumps({'linkage': args.linkage}))
print('completed ' + args.linkage, flush=True)
if settings['spawn']:
    child_code = "import pathlib, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(1); pathlib.Path(" + repr(str(barrier / ('leaked-' + args.linkage))) + ").write_text('leaked')"
    subprocess.Popen([sys.executable, '-c', child_code])
if settings['hang']:
    time.sleep(60)
sys.exit(7 if settings['fail'] == args.linkage else 0)
'''


class PairTest(unittest.TestCase):
    def fixture(self, directory, fail=None, spawn=False, hang=False):
        root = directory / 'source'
        (root / 'scripts').mkdir(parents=True)
        barrier = directory / 'barrier'
        barrier.mkdir()
        (root / 'settings.json').write_text(json.dumps(dict(barrier=str(barrier), fail=fail,
                                                          spawn=spawn, hang=hang)))
        (root / 'scripts' / 'manager_protocol_test.py').write_text(WORKER)
        archive = directory / 'inputs.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            for source in root.iterdir():
                output.add(source, arcname=source.name)
        return root, archive

    def check_pair(self, fail):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, archive = self.fixture(directory, fail)
            status = PAIRED.run_pair(root, archive, directory, 'protocol-bios-modern-lane0')
            self.assertEqual(status, 1 if fail else 0)
            evidence = root / 'build' / 'paired-network' / 'protocol-bios-modern-lane0'
            report = json.loads((evidence / 'results.json').read_text())
            self.assertEqual(report['success'], fail is None)
            self.assertIsNone(report['error'])
            self.assertNotEqual(report['workers']['static']['workspace'], report['workers']['dynamic']['workspace'])
            for linkage in ('static', 'dynamic'):
                expected = 7 if fail == linkage else 0
                self.assertEqual(report['workers'][linkage]['returncode'], expected)
                saved = json.loads((evidence / linkage / 'manager-protocol-results.json').read_text())
                self.assertEqual(saved['linkage'], linkage)
                packets = json.loads((evidence / linkage / 'manager-protocol-packets.json').read_text())
                self.assertEqual(packets['linkage'], linkage)
                self.assertIn('completed ' + linkage, (evidence / linkage / 'worker.log').read_text())
            self.assertFalse(Path(report['workers']['dynamic']['workspace']).exists())

    def test_both_linkages_run_concurrently_with_independent_fixtures(self):
        self.check_pair(None)

    def test_dynamic_failure_retains_both_workers_and_packet_evidence(self):
        self.check_pair('dynamic')

    def test_static_failure_retains_both_workers_and_packet_evidence(self):
        self.check_pair('static')

    def test_rejects_unknown_cells_before_creating_workspaces(self):
        for suite in ('boot', 'protocol-bios-modern-lane2', 'link-bios-modern-lane0-static', '../link'):
            with self.subTest(suite=suite), self.assertRaises(ValueError):
                PAIRED.parameters(suite)

    def test_rejects_missing_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaises(ValueError):
                PAIRED.run_pair(directory, directory / 'absent.tar.gz', directory, 'link-bios-modern-lane0')
            self.assertFalse((directory / 'build').exists())

    def test_reaps_descendants_after_successful_worker_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, archive = self.fixture(directory, spawn=True)
            self.assertEqual(PAIRED.run_pair(root, archive, directory, 'protocol-bios-modern-lane0'), 0)
            time.sleep(1.2)
            self.assertEqual(list((directory / 'barrier').glob('leaked-*')), [])

    def test_signal_interruption_stops_both_workers_and_retains_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, archive = self.fixture(directory, hang=True)
            driver = '''import importlib.util, pathlib, signal, sys
spec = importlib.util.spec_from_file_location('paired', sys.argv[1])
paired = importlib.util.module_from_spec(spec)
spec.loader.exec_module(paired)
signal.signal(signal.SIGTERM, paired.interrupted)
raise SystemExit(paired.run_pair(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]),
                                pathlib.Path(sys.argv[4]), 'protocol-bios-modern-lane0'))
'''
            process = subprocess.Popen([sys.executable, '-c', driver, str(SCRIPT), str(root),
                                        str(archive), str(directory)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 10
                while not all((directory / 'barrier' / linkage).exists() for linkage in ('static', 'dynamic')):
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
                os.kill(process.pid, signal.SIGTERM)
                self.assertEqual(process.wait(timeout=10), 1)
                evidence = root / 'build' / 'paired-network' / 'protocol-bios-modern-lane0'
                report = json.loads((evidence / 'results.json').read_text())
                self.assertFalse(report['success'])
                self.assertIn('InterruptedError', report['error'])
                for linkage in ('static', 'dynamic'):
                    self.assertLess(report['workers'][linkage]['returncode'], 0)
                    self.assertTrue((evidence / linkage / 'worker.log').is_file())
                self.assertFalse(Path(report['workers']['dynamic']['workspace']).exists())
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    unittest.main()

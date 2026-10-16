# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual worker concurrency, isolated fixtures and failure evidence."""
import importlib.util
import hashlib
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
from unittest.mock import patch


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

NORMAL_WORKER = '''import argparse, gzip, hashlib, json, pathlib, sys, time
parser = argparse.ArgumentParser()
parser.add_argument('--firmware')
parser.add_argument('--transport')
parser.add_argument('--root', default='both')
parser.add_argument('--scenario', nargs='+', default=['no-nic','no-server','missing','healthy'])
args = parser.parse_args()
root = pathlib.Path.cwd()
settings = json.loads((root / 'settings.json').read_text())
barrier = pathlib.Path(settings['barrier'])
worker = args.transport
other = 'legacy' if worker == 'modern' else 'modern'
build = root / 'build'
build.mkdir(exist_ok=True)
(barrier / worker).write_text('ready')
deadline = time.monotonic() + 10
while not (barrier / other).exists():
    assert time.monotonic() < deadline, 'both transport workers must run at once'
    time.sleep(.02)
fixture = build / ('normal-init-login-' + worker)
fixture.mkdir()
data = {'root.cpio': b'root-' + worker.encode(), 'seed.raw': b'seed-' + worker.encode(),
        'axiom64-normal-init-ram.iso': b'ram-' + worker.encode(),
        'axiom64-normal-init-ext2.iso': b'ext2-' + worker.encode(),
        'saved.raw.gz': gzip.compress(b'disk-' + worker.encode())}
for name, value in data.items():
    (fixture / name).write_bytes(value)
for name in ('axiom64-normal-init-ram.iso','axiom64-normal-init-ext2.iso'):
    (build / name).write_bytes(data[name])
(build / 'root-disk.raw').write_bytes(data['seed.raw'])
if settings.get('changed_alias') == worker:
    (build / 'root-disk.raw').write_bytes(b'actual-rejected-seed-' + worker.encode())
inputs = dict(image_sha256={key: hashlib.sha256(data['axiom64-normal-init-'+key+'.iso']).hexdigest()
                           for key in ('ram','ext2')}, seed_sha256=hashlib.sha256(data['seed.raw']).hexdigest())
(fixture / 'inputs.json').write_text(json.dumps(inputs))
rows = [dict(scenario=scenario,firmware=args.firmware,transport=worker,root=kind,
             passed=True,directory=str(fixture),acceleration=dict(used='tcg'))
        for kind in (('ram','ext2') if args.root=='both' else (args.root,)) for scenario in args.scenario]
if settings['normal_missing']:
    rows.pop()
(build / ('normal-init-'+args.firmware+'-results.json')).write_text(json.dumps(rows))
print('completed ' + worker, flush=True)
sys.exit(7 if settings['fail'] == worker else 0)
'''


class PairTest(unittest.TestCase):
    def fixture(self, directory, fail=None, spawn=False, hang=False, normal_missing=False, changed_alias=None):
        root = directory / 'source'
        (root / 'scripts').mkdir(parents=True)
        barrier = directory / 'barrier'
        barrier.mkdir()
        (root / 'settings.json').write_text(json.dumps(dict(barrier=str(barrier), fail=fail,
                                                          spawn=spawn, hang=hang,
                                                          normal_missing=normal_missing,
                                                          changed_alias=changed_alias)))
        (root / 'scripts' / 'manager_protocol_test.py').write_text(WORKER)
        (root / 'scripts' / 'normal_manager_test.py').write_text(NORMAL_WORKER)
        (root / 'build').mkdir()
        (root / 'build/axiom64.elf').write_bytes(b'prepared-kernel')
        (root / 'build/rootfs.cpio').write_bytes(b'prepared-production-root')
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

    def check_normal_pair(self, fail=None, missing=False):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, archive = self.fixture(directory, fail=fail, normal_missing=missing)
            old = root / 'build' / 'normal-init-login-preexisting'
            old.mkdir(parents=True)
            (old / 'checkpoint').write_text('keep')
            status = PAIRED.run_pair(root, archive, directory, 'normal-init-bios')
            self.assertEqual(status, int(fail is not None or missing))
            evidence = root / 'build' / 'paired-network' / 'normal-init-bios'
            report = json.loads((evidence / 'results.json').read_text())
            self.assertEqual(report['success'], status == 0)
            self.assertEqual((old / 'checkpoint').read_text(), 'keep')
            self.assertEqual(set(report['workers']), {'modern', 'legacy'})
            for worker in ('modern', 'legacy'):
                record = report['workers'][worker]
                rows = json.loads((root / record['evidence'] / 'normal-init-bios-results.json').read_text())
                self.assertEqual(len(rows), 7 if missing else 8)
                self.assertEqual(record['returncode'], 7 if worker == fail else 0)
                saved = record['fixtures']
                self.assertTrue(saved)
                for original, retained in saved.items():
                    path = root / retained['path']
                    self.assertTrue(path.is_file(), original)
                    self.assertEqual(path.stat().st_size, retained['bytes'])
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), retained['sha256'])
                self.assertFalse((root / 'build' / ('normal-init-login-' + worker)).exists())
            self.assertFalse(Path(report['workers']['legacy']['workspace']).exists())
            self.assertFalse((root / 'build/axiom64-normal-init-ram.iso').exists())
            self.assertFalse((root / 'build/root-disk.raw').exists())

    def test_normal_transports_retain_every_case_and_actual_fixture_in_isolated_workers(self):
        self.check_normal_pair()

    def test_normal_worker_failure_still_retains_both_complete_fixture_trees(self):
        self.check_normal_pair(fail='legacy')

    def test_normal_missing_case_is_failure_even_when_worker_exits_successfully(self):
        self.check_normal_pair(missing=True)

    def test_normal_workers_reject_different_prepared_inputs_before_booting(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, archive = self.fixture(directory)
            (root / 'build/axiom64.elf').write_bytes(b'changed-kernel')
            self.assertEqual(PAIRED.run_pair(root, archive, directory, 'normal-init-bios'), 1)
            report = json.loads((root / 'build/paired-network/normal-init-bios/results.json').read_text())
            self.assertFalse(report['success'])
            self.assertIn('identical prepared kernel and root inputs', report['error'])
            self.assertEqual(report['workers'], {})
            self.assertFalse(any((directory / 'barrier').iterdir()))

    def test_normal_retention_collision_keeps_both_existing_and_failed_fixture_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, archive = self.fixture(directory)
            existing = root / 'build/normal-init-workers/normal-init-bios/legacy/normal-init-login-legacy'
            existing.mkdir(parents=True)
            (existing / 'checkpoint').write_text('keep-existing')
            self.assertEqual(PAIRED.run_pair(root, archive, directory, 'normal-init-bios'), 1)
            report = json.loads((root / 'build/paired-network/normal-init-bios/results.json').read_text())
            self.assertFalse(report['success'])
            self.assertEqual((existing / 'checkpoint').read_text(), 'keep-existing')
            saved = report['workers']['legacy']['unverified_fixture_archive']
            path = root / saved['path']
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), saved['sha256'])
            with tarfile.open(path) as retained:
                self.assertEqual(retained.extractfile('normal-init-login-legacy/seed.raw').read(), b'seed-legacy')
            self.assertFalse(Path(report['workers']['legacy']['workspace']).exists())

    def test_failed_report_copy_keeps_original_worker_workspace_and_fixtures(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, archive = self.fixture(directory)
            copy = PAIRED.shutil.copy2

            def reject_legacy_report(source, destination, *args, **kwargs):
                if destination.parent.name == 'legacy' and source.name == 'normal-init-bios-results.json':
                    raise OSError('owned report destination rejects copying')
                return copy(source, destination, *args, **kwargs)

            with patch.object(PAIRED.shutil, 'copy2', side_effect=reject_legacy_report):
                self.assertEqual(PAIRED.run_pair(root, archive, directory, 'normal-init-bios'), 1)
            report = json.loads((root / 'build/paired-network/normal-init-bios/results.json').read_text())
            self.assertFalse(report['success'])
            workspace = Path(report['preserved_temporary_workspace'])
            self.assertTrue(workspace.is_dir())
            original = workspace / 'build/normal-init-bios-results.json'
            self.assertEqual(len(json.loads(original.read_text())), 8)
            self.assertIn('rejects copying', report['capture_failures'][0])
            for record in report['workers'].values():
                for saved in record['fixtures'].values():
                    self.assertEqual(hashlib.sha256((root / saved['path']).read_bytes()).hexdigest(), saved['sha256'])

    def test_rejected_alias_is_kept_after_original_fixture_tree_already_moved(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, archive = self.fixture(directory, changed_alias='legacy')
            self.assertEqual(PAIRED.run_pair(root, archive, directory, 'normal-init-bios'), 1)
            report = json.loads((root / 'build/paired-network/normal-init-bios/results.json').read_text())
            self.assertFalse(report['success'])
            saved = report['workers']['legacy']['unverified_fixture_archive']
            with tarfile.open(root / saved['path']) as retained:
                self.assertEqual(retained.extractfile('root-disk.raw').read(), b'actual-rejected-seed-legacy')
            original = root / 'build/normal-init-workers/normal-init-bios/legacy/normal-init-login-legacy/seed.raw'
            self.assertEqual(original.read_bytes(), b'seed-legacy')

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

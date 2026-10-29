# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real overlap, immutable inputs and owned process-group retirement."""
from contextlib import redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'ci/network_window.py'
SPEC = importlib.util.spec_from_file_location('network_window', SCRIPT)
WINDOW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WINDOW)
WORKER = '''from pathlib import Path
import json,sys,time
name,mode=sys.argv[1:]
root=Path.cwd()
(root/(name+'.ready')).write_text('ready')
other='guest' if name=='native' else 'native'
deadline=time.monotonic()+5
while not (root/(other+'.ready')).exists():
    assert time.monotonic()<deadline,'the other real worker must start before either finishes'
    time.sleep(.01)
if mode=='change':(root/'build/input').write_bytes(b'changed')
if mode=='descendant':
    import subprocess
    code="import pathlib,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(.8);pathlib.Path('leaked').write_text('bad')"
    subprocess.Popen([sys.executable,'-c',code])
time.sleep(.1)
print(name+' complete',flush=True)
sys.exit(7 if mode=='fail' else 0)
'''


class NetworkWindowTest(unittest.TestCase):
    def exercise(self, native='ok', guest='ok', change=False):
        with tempfile.TemporaryDirectory(prefix='axiom-network-window-') as temporary:
            root = Path(temporary)
            (root / 'build').mkdir()
            (root / 'build/input').write_bytes(b'immutable')
            worker = root / 'worker.py'
            worker.write_text(WORKER)
            commands = {name: [sys.executable, str(worker), name, mode]
                        for name, mode in (('native', native), ('guest', guest))}
            with redirect_stdout(io.StringIO()):
                status = WINDOW.run_window(root, commands, [root / 'build/input'])
            report = json.loads((root / 'build/network-window/results.json').read_text())
            self.assertEqual(report['original_complete_commands'], False)
            self.assertEqual(set(report['workers']), {'native', 'guest'})
            self.assertGreater(report['overlap_ns'], 0)
            if native == 'descendant' or guest == 'descendant':
                time.sleep(1)
                self.assertFalse((root / 'leaked').exists())
            return status, report

    def test_both_real_workers_overlap_and_complete(self):
        status, report = self.exercise()
        self.assertEqual(status, 0)
        self.assertTrue(report['passed'])
        self.assertTrue(report['inputs_unchanged'])

    def test_native_failure_is_never_hidden_by_guest_success(self):
        status, report = self.exercise(native='fail')
        self.assertEqual(status, 1)
        self.assertFalse(report['passed'])
        self.assertEqual(report['workers']['native']['returncode'], 7)

    def test_guest_failure_is_never_hidden_by_native_success(self):
        status, report = self.exercise(guest='fail')
        self.assertEqual(status, 1)
        self.assertFalse(report['passed'])
        self.assertEqual(report['workers']['guest']['returncode'], 7)

    def test_changed_compiler_product_rejects(self):
        status, report = self.exercise(guest='change')
        self.assertEqual(status, 1)
        self.assertFalse(report['inputs_unchanged'])

    def test_exited_worker_cannot_leave_a_descendant(self):
        status, report = self.exercise(native='descendant')
        self.assertEqual(status, 0)
        self.assertTrue(report['passed'])

    def test_failed_start_retires_an_already_started_worker(self):
        with tempfile.TemporaryDirectory(prefix='axiom-network-start-') as temporary:
            root = Path(temporary)
            commands = {'native': [sys.executable, '-c', 'import time;time.sleep(60)'],
                        'guest': [str(root / 'missing-executable')]}
            with redirect_stdout(io.StringIO()):
                self.assertEqual(WINDOW.run_window(root, commands), 1)
            report = json.loads((root / 'build/network-window/results.json').read_text())
            self.assertIn('FileNotFoundError', report['error'])
            self.assertIsNotNone(report['workers']['native']['returncode'])


class CompletionContractTest(unittest.TestCase):
    def setUp(self):
        from network_matrix import cases
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom-window-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        names = ['build/' + name for name in WINDOW.PRODUCTS]
        sources = ['scripts/ci/network_window.py', 'scripts/ci/paired_network.py',
                   'scripts/network_matrix.py', 'scripts/ipv4_fragment_native.py',
                   'scripts/native_icmp_budget_test.py', 'Makefile']
        for name in names + sources:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'owned fixture input')
        self.rows = [dict(firmware=c['firmware'], transport=c['transport'], models=c['models'],
            rx_queue=c['queue'], wrap=c.get('wrap', False), fault=c.get('fault'),
            pressure=c.get('pressure', False), status_feature=c.get('status', True), host_mtu=c.get('mtu', 0),
            passed=True, returncode=1, timed_out=False, error=None, missing=[]) for c in cases()]
        self.ledger = self.root / 'build/network-results.json'
        self.ledger.write_text(json.dumps(self.rows))
        commands = {'native': ['sudo', '-n', 'make', '-j1', 'test-native-icmp-budget',
                              'test-ipv4-fragments-native'], 'guest': ['make', 'test-network']}
        self.report = dict(passed=True, original_complete_commands=True, inputs_unchanged=True,
            original_clocks_and_deadlines_preserved=True, start_monotonic_ns=100, end_monotonic_ns=500,
            overlap_ns=200, immutable_products={name: WINDOW.digest(self.root / name) for name in names},
            source_sha256={name: WINDOW.digest(self.root / name) for name in sources},
            workers={name: dict(command=command, pid=n+1, returncode=0,
                start_monotonic_ns=100+n*100, end_monotonic_ns=400+n*100)
                for n, (name, command) in enumerate(commands.items())})

    def test_complete_original_commands_and_all_guest_cells_pass(self):
        self.assertEqual(WINDOW.validate_window(self.root, self.report), 46)

    def test_false_pass_bits_do_not_hide_contradictory_metadata(self):
        def incomplete(data):
            data['source_sha256'].pop('Makefile')
        def command(data):
            data['workers']['native']['command'].pop()
        mutations = [incomplete, command,
            lambda data: data['immutable_products'].pop('build/ipv4-native'),
            lambda data: data['workers']['guest'].__setitem__('returncode', 7),
            lambda data: data['workers'].pop('guest'),
            lambda data: data.__setitem__('overlap_ns', 999),
            lambda data: data['workers']['native'].__setitem__('end_monotonic_ns', 150)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                data = deepcopy(self.report)
                mutation(data)
                with self.assertRaises(ValueError):
                    WINDOW.validate_window(self.root, data)

    def test_missing_duplicate_and_failed_guest_cells_reject(self):
        variants = [self.rows[:-1], self.rows[:-1] + [deepcopy(self.rows[0])], deepcopy(self.rows)]
        variants[-1][0]['passed'] = False
        for rows in variants:
            with self.subTest(rows=len(rows)):
                self.ledger.write_text(json.dumps(rows))
                with self.assertRaises(ValueError):
                    WINDOW.validate_window(self.root, self.report)


if __name__ == '__main__':
    unittest.main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise capacity ownership with real files and locks, without host sysctl writes."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import native_neighbor_capacity as capacity

OUTPUT = None
HEADER = 'entries allocs destroys forced_gc_runs table_fulls\n'


def fixture_paths(directory):
    return dict(STAT_PATH=directory / 'statistics', SETTINGS_PATH=directory / 'settings',
                SELF_NAMESPACE=directory / 'initial-netns',
                INITIAL_NAMESPACE=directory / 'initial-netns',
                LOCK_PATH=directory / 'locks' / 'capacity.lock')


class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='axiom-neighbor-capacity-')
        self.directory = Path(self.temporary.name)
        (self.directory / 'settings').mkdir()
        (self.directory / 'locks').mkdir()
        (self.directory / 'initial-netns').touch()
        (self.directory / 'statistics').write_text(HEADER + '64 80 1c 0 0\n64 1 0 0 0\n')
        for name, value in zip(capacity.SETTINGS, (128, 512, 1024, 30, 30000, 1000, 60, 5)):
            (self.directory / 'settings' / name).write_text(str(value) + '\n')
        self.patches = patch.multiple(capacity, **fixture_paths(self.directory))
        self.patches.start()
        self.output = OUTPUT / self._testMethodName
        self.output.mkdir()

    def tearDown(self):
        self.patches.stop()
        self.temporary.cleanup()

    def value(self):
        return int((self.directory / 'settings/gc_thresh3').read_text())

    def receipt(self):
        return json.loads((self.output / 'neighbor-capacity.json').read_text())

    def test_statistics_shared_entries_and_per_cpu_counters(self):
        result = capacity.parse_statistics(HEADER + '10 20 10 3 1\n12 40 2e 4 2\n')
        self.assertEqual(result['entries'], 18)
        self.assertEqual(result['cpu_rows'], 2)
        self.assertEqual(result['counters']['table_fulls'], 3)
        self.assertEqual(result['counters']['forced_gc_runs'], 7)

    def test_reject_malformed_statistics(self):
        samples = ('', HEADER, HEADER + '1 2 3\n', HEADER + 'x 0 0 0 0\n',
                   HEADER + '100000000 0 0 0 0\n', 'entries entries table_fulls\n1 1 1\n',
                   'x' * ((1 << 20) + 1))
        for sample in samples:
            with self.subTest(sample=sample[:60]), self.assertRaises(capacity.CapacityError):
                capacity.parse_statistics(sample)

    def test_reserve_all_selected_profiles_and_restore(self):
        with capacity.ipv6_neighbor_capacity(self.output, 3) as receipt:
            self.assertEqual(self.value(), 100 + 3 * 1024)
            self.assertTrue(receipt['body_started'])
            self.assertEqual(receipt['before']['statistics']['entries'], 100)
            (self.directory / 'statistics').write_text(HEADER + 'c8 100 1c 4 0\nc8 2 0 2 0\n')
        self.assertEqual(self.value(), 1024)
        receipt = self.receipt()
        self.assertTrue(receipt['passed'] and receipt['restored'] and receipt['other_settings_unchanged'])
        self.assertEqual(receipt['final']['counter_deltas']['table_fulls'], 0)
        self.assertEqual(receipt['final']['counter_deltas']['forced_gc_runs'], 6)
        self.assertEqual(receipt['before']['settings_raw'], receipt['restored_state']['settings_raw'])
        self.assertEqual(len(receipt['helper_sha256']), 64)

    def test_already_adequate_capacity_is_not_written(self):
        (self.directory / 'settings/gc_thresh3').write_text('8192\n')
        with patch.object(capacity, '_write_capacity', wraps=capacity._write_capacity) as writer:
            with capacity.ipv6_neighbor_capacity(self.output, 3):
                self.assertEqual(self.value(), 8192)
            writer.assert_not_called()
        self.assertFalse(self.receipt()['changed'])
        self.assertTrue(self.receipt()['restored'])

    def test_restore_after_body_failure(self):
        with self.assertRaisesRegex(ValueError, 'original client failure'):
            with capacity.ipv6_neighbor_capacity(self.output, 2):
                raise ValueError('original client failure')
        self.assertEqual(self.value(), 1024)
        self.assertTrue(self.receipt()['restored'])
        self.assertFalse(self.receipt()['body_completed'] or self.receipt()['passed'])

    def test_failed_write_before_change_prevents_body(self):
        with patch.object(capacity, '_write_capacity', side_effect=OSError('write rejected')):
            with self.assertRaisesRegex(OSError, 'write rejected'):
                with capacity.ipv6_neighbor_capacity(self.output, 2):
                    self.fail('body ran after rejected write')
        self.assertEqual(self.value(), 1024)
        self.assertTrue(self.receipt()['restored'])
        self.assertFalse(self.receipt()['body_started'])

    def test_failed_write_after_change_is_restored(self):
        original_write = capacity._write_capacity
        calls = []

        def failed_write(value):
            calls.append(value)
            original_write(value)
            if len(calls) == 1:
                raise OSError('write completion lost')

        with patch.object(capacity, '_write_capacity', side_effect=failed_write):
            with self.assertRaisesRegex(OSError, 'write completion lost'):
                with capacity.ipv6_neighbor_capacity(self.output, 2):
                    self.fail('body ran after failed write completion')
        self.assertEqual(calls, [2148, 1024])
        self.assertEqual(self.value(), 1024)
        self.assertTrue(self.receipt()['restored'])

    def test_write_readback_mismatch_prevents_body(self):
        with patch.object(capacity, '_write_capacity', return_value=None):
            with self.assertRaisesRegex(capacity.CapacityError, 'did not read back'):
                with capacity.ipv6_neighbor_capacity(self.output, 2):
                    self.fail('body ran without verified capacity')
        self.assertEqual(self.value(), 1024)
        self.assertTrue(self.receipt()['restored'])

    def test_snapshot_failure_after_write_still_restores(self):
        original_snapshot = capacity._snapshot
        calls = []

        def failed_snapshot():
            calls.append(None)
            if len(calls) == 2:
                raise OSError('statistics read failed')
            return original_snapshot()

        with patch.object(capacity, '_snapshot', side_effect=failed_snapshot):
            with self.assertRaisesRegex(OSError, 'statistics read failed'):
                with capacity.ipv6_neighbor_capacity(self.output, 2):
                    self.fail('body ran without applied snapshot')
        self.assertEqual(self.value(), 1024)
        self.assertTrue(self.receipt()['restored'])

    def test_external_change_is_not_overwritten(self):
        with self.assertRaisesRegex(capacity.CapacityError, 'changed externally'):
            with capacity.ipv6_neighbor_capacity(self.output, 2):
                (self.directory / 'settings/gc_thresh3').write_text('4096\n')
        self.assertEqual(self.value(), 4096)
        self.assertFalse(self.receipt()['restored'])

    def test_other_settings_change_is_reported_without_restoring_them(self):
        with self.assertRaisesRegex(capacity.CapacityError, 'another neighbor setting changed'):
            with capacity.ipv6_neighbor_capacity(self.output, 2):
                (self.directory / 'settings/gc_interval').write_text('31\n')
        self.assertEqual(self.value(), 1024)
        self.assertEqual((self.directory / 'settings/gc_interval').read_text(), '31\n')
        self.assertFalse(self.receipt()['other_settings_unchanged'])

    def test_external_soft_limit_prevents_incompatible_restoration(self):
        with self.assertRaisesRegex(capacity.CapacityError, 'prevent ordered capacity restoration'):
            with capacity.ipv6_neighbor_capacity(self.output, 2):
                (self.directory / 'settings/gc_thresh2').write_text('2048\n')
        self.assertEqual(self.value(), 2148)
        self.assertEqual((self.directory / 'settings/gc_thresh2').read_text(), '2048\n')
        self.assertFalse(self.receipt()['restored'])

    def test_cohort_overflow_is_rejected_and_capacity_restored(self):
        with self.assertRaisesRegex(capacity.CapacityError, 'overflow counter changed'):
            with capacity.ipv6_neighbor_capacity(self.output, 2):
                (self.directory / 'statistics').write_text(HEADER + '64 80 1c 1 1\n64 1 0 0 0\n')
        self.assertEqual(self.value(), 1024)
        self.assertEqual(self.receipt()['cohort_table_fulls_delta'], 1)
        self.assertTrue(self.receipt()['restored'])
        self.assertFalse(self.receipt()['passed'])

    def test_sigterm_restores_capacity_and_previous_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        with self.assertRaisesRegex(capacity.CapacityError, 'SIGTERM interrupted'):
            with capacity.ipv6_neighbor_capacity(self.output, 2):
                os.kill(os.getpid(), signal.SIGTERM)
        self.assertEqual(self.value(), 1024)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)
        self.assertTrue(self.receipt()['restored'])

    def test_restoration_write_failure_is_not_success(self):
        original_write = capacity._write_capacity

        def failed_restore(value):
            if value == 1024:
                raise OSError('restore rejected')
            original_write(value)

        with patch.object(capacity, '_write_capacity', side_effect=failed_restore):
            with self.assertRaisesRegex(capacity.CapacityError, 'restore rejected'):
                with capacity.ipv6_neighbor_capacity(self.output, 2):
                    pass
        self.assertEqual(self.value(), 2148)
        self.assertFalse(self.receipt()['restored'] or self.receipt()['passed'])

    def test_concurrent_process_cannot_take_the_real_lock(self):
        with capacity.ipv6_neighbor_capacity(self.output, 2):
            child = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()),
                                    '--lock-child', str(self.directory)],
                                   capture_output=True, text=True, timeout=10)
            self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
            self.assertIn('LOCK_CONFLICT_REJECTED', child.stdout)
            self.assertEqual(self.value(), 2148)
        self.assertEqual(self.value(), 1024)

    def test_symlink_lock_is_rejected(self):
        target = self.directory / 'preserve-me'
        target.write_text('unchanged\n')
        capacity.LOCK_PATH.symlink_to(target)
        with self.assertRaises(OSError):
            with capacity.ipv6_neighbor_capacity(self.output, 2):
                self.fail('symlink lock admitted')
        self.assertEqual(target.read_text(), 'unchanged\n')
        self.assertEqual(self.value(), 1024)

    def test_real_child_network_namespace_is_rejected(self):
        child = subprocess.run(['unshare', '--net', sys.executable, '-B',
                                str(Path(__file__).resolve()), '--namespace-child', str(self.output)],
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        self.assertIn('CHILD_NAMESPACE_REJECTED', child.stdout)

    def test_capacity_bound_prevents_writes(self):
        (self.directory / 'statistics').write_text(HEADER + '100000 1 0 0 0\n')
        with patch.object(capacity, '_write_capacity') as writer:
            with self.assertRaisesRegex(capacity.CapacityError, 'finite capacity bound'):
                with capacity.ipv6_neighbor_capacity(self.output, 2):
                    self.fail('over-limit capacity admitted')
            writer.assert_not_called()
        self.assertEqual(self.value(), 1024)

    def test_existing_receipt_is_not_replaced(self):
        marker = self.output / 'neighbor-capacity.json'
        marker.write_text('preserved\n')
        with self.assertRaises(FileExistsError):
            with capacity.ipv6_neighbor_capacity(self.output, 2):
                self.fail('existing evidence was replaced')
        self.assertEqual(marker.read_text(), 'preserved\n')


def main():
    global OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/native-neighbor-capacity-tests')
    parser.add_argument('--lock-child', type=Path)
    parser.add_argument('--namespace-child', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('capacity ownership tests require root for actual lock ownership')
    if args.lock_child:
        with patch.multiple(capacity, **fixture_paths(args.lock_child)):
            try:
                with capacity.ipv6_neighbor_capacity(args.lock_child / 'second-parent', 2):
                    raise AssertionError('second process acquired the occupied lock')
            except capacity.CapacityError as error:
                if 'another native cohort owns' not in str(error):
                    raise
                print('LOCK_CONFLICT_REJECTED')
        return 0
    if args.namespace_child:
        try:
            with capacity.ipv6_neighbor_capacity(args.namespace_child, 2):
                raise AssertionError('child namespace acquired a global setting')
        except capacity.CapacityError as error:
            if 'initial network namespace' not in str(error):
                raise
            print('CHILD_NAMESPACE_REJECTED')
        return 0
    OUTPUT = args.directory.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=False)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CapacityTests))
    (OUTPUT / 'receipt.json').write_text(json.dumps(dict(passed=result.wasSuccessful(),
        tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        real_file_locks=True, host_sysctl_writes=False), indent=2) + '\n')
    if result.wasSuccessful():
        print(f'NATIVE_NEIGHBOR_CAPACITY_CONTROLS_PASS cases={result.testsRun} real_locks_no_host_writes')
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())

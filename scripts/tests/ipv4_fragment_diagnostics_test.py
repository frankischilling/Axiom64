# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual acknowledgement failures without changing protocol deadlines."""
from pathlib import Path
import argparse
import io
import errno
import hashlib
import json
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
from contextlib import ExitStack, redirect_stdout

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from native_ipv4_state import FILES, NativeIpv4State
import ipv4_fragment_native as native
import tempfile
DIRECTORY = ROOT / 'build/ipv4-fragment-diagnostics'


class AcknowledgementFailures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DIRECTORY.mkdir(parents=True, exist_ok=False)
        snapshots = DIRECTORY / 'source'
        snapshots.mkdir()
        fingerprints = {}
        for name in ('ipv4_fragments.c', 'ipv4_fragments.h'):
            original = ROOT / 'userspace/tests/net' / name
            data = original.read_bytes()
            (snapshots / name).write_bytes(data)
            fingerprints[name] = hashlib.sha256(data).hexdigest()
        program = DIRECTORY / 'acknowledgement.c'
        program.write_text(r'''#include "source/ipv4_fragments.c"
#include <signal.h>

static void interrupted(int signal_number) { (void)signal_number; }

int main(int argc, char** argv) {
    int descriptors[2];
    require(argc == 2 && pipe(descriptors) == 0, "diagnostic setup");
    int timeout = 0;
    if (!strcmp(argv[1], "invalid"))
        require(close(descriptors[0]) == 0, "diagnostic close");
    if (!strcmp(argv[1], "interrupted")) {
        struct sigaction action = {0};
        action.sa_handler = interrupted;
        require(sigaction(SIGALRM, &action, NULL) == 0, "diagnostic signal");
        ualarm(10000, 0);
        timeout = 1000;
    }
    errno = EMSGSIZE;
    acknowledgement(descriptors[0], 1, "FE", 1, 1, timeout);
    return 99;
}
''')
        binary = DIRECTORY / 'acknowledgement'
        command = [shutil.which('gcc') or 'gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                   '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', str(program), '-o', str(binary)]
        result = subprocess.run(command, capture_output=True)
        (DIRECTORY / 'compile.log').write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise AssertionError(result.stderr.decode())
        (DIRECTORY / 'source-binding.json').write_text(json.dumps(dict(
            scope='host failure-reporting regression; no guest or native protocol acceptance',
            source_sha256=fingerprints, compiler_command=command,
            executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest()), indent=2) + '\n')
        cls.binary = binary

    def failure(self, case, expected_errno, expected_poll, expected_events, timeout):
        result = subprocess.run([str(self.binary), case], capture_output=True)
        output = result.stdout + result.stderr
        (DIRECTORY / (case + '.log')).write_bytes(output)
        self.assertEqual(result.returncode, 1)
        expected = (f'IPV4_FRAGMENT_ACK_FAIL index=2 tag=FE test=1 phase=1 timeout_ms={timeout} '
                    f'poll={expected_poll} revents={expected_events:x} errno={expected_errno}\n')
        self.assertIn(expected.encode(), output)
        self.assertIn(f'IPV4_FRAGMENT_FAIL output acknowledgement readiness errno={expected_errno}\n'.encode(), output)

    def test_timeout_does_not_report_stale_emsgsize(self):
        self.failure('timeout', errno.ETIMEDOUT, 0, 0, 0)

    def test_invalid_descriptor_reports_actual_poll_events(self):
        self.failure('invalid', errno.EIO, 1, 0x20, 0)

    def test_interrupted_poll_preserves_the_syscall_errno(self):
        self.failure('interrupted', errno.EINTR, -1, 0, 1000)


class CounterEvidence(unittest.TestCase):
    def test_real_read_only_linux_counters_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = NativeIpv4State(directory)
            collector.snapshot('before failure')
            collector.snapshot('after failure')
            report = collector.close()
            path = Path(directory) / report['path']
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertTrue(report['complete'])
            self.assertEqual(report['records'], 2)
            self.assertEqual(report['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            for row in rows:
                self.assertEqual(set(row['files']), set(FILES))
                self.assertTrue(row['files']['net/snmp'].startswith('Ip: '))
                self.assertTrue(row['files']['net/sockstat'].startswith('sockets: '))
                self.assertLessEqual(row['clock_begin']['monotonic_after_ns'], row['clock_end']['monotonic_ns'])
            self.assertEqual([row['reason'] for row in rows], ['before failure', 'after failure'])

    def test_unavailable_counters_remain_explicit_and_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = NativeIpv4State(directory, proc=Path(directory) / 'unavailable-proc')
            collector.snapshot('client failed')
            report = collector.close()
            row = json.loads((Path(directory) / report['path']).read_text())
            self.assertFalse(report['complete'])
            self.assertEqual(set(row['read_errors']), set(FILES))
            self.assertEqual(row['files'], {})
            self.assertEqual(row['reason'], 'client failed')

    def test_existing_original_evidence_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'native-kernel-state.jsonl'
            original = b'original failed observation\n'
            path.write_bytes(original)
            with self.assertRaises(FileExistsError):
                NativeIpv4State(directory)
            self.assertEqual(path.read_bytes(), original)


class FailedChildRetention(unittest.TestCase):
    def failed_child(self, failure):
        target = DIRECTORY / ('failed-child-' + failure)
        real_open, real_read = native.os.open, Path.read_text
        actual_kernel = native.platform.uname()._asdict()

        def descriptor(name, flags, *args):
            return real_open('/dev/null' if name == '/dev/net/tun' else name, flags, *args)

        def read(path, *args, **kwargs):
            if str(path) == '/proc/sys/net/ipv4/ipfrag_time':
                return '60\n'
            if str(path) == '/proc/sys/net/ipv4/route/mtu_expires':
                return '600\n'
            return real_read(path, *args, **kwargs)

        with ExitStack() as stack:
            uname = stack.enter_context(patch.object(native.platform, 'uname'))
            uname.return_value._asdict.return_value = actual_kernel
            stack.enter_context(patch.object(native, 'client', return_value=[shutil.which('true'), '--fragments']))
            stack.enter_context(patch.object(native, 'query_model', return_value='read-only'))
            stack.enter_context(patch.object(native.os, 'open', side_effect=descriptor))
            stack.enter_context(patch.object(Path, 'read_text', read))
            stack.enter_context(patch.object(native.fcntl, 'ioctl'))
            stack.enter_context(patch.object(native.selectors, 'DefaultSelector'))
            stack.enter_context(patch.object(native.subprocess, 'run'))
            launched = stack.enter_context(patch.object(native.subprocess, 'Popen'))
            launched.return_value.poll.return_value = 1
            launched.return_value.returncode = 1
            capture = stack.enter_context(patch.object(native, 'Capture'))
            capture.return_value.close.return_value = dict(packets=0, dropped=0)
            if failure == 'capture':
                capture.return_value.close.side_effect = RuntimeError('injected capture shutdown failure')
            link = dict(stats64=dict(tx=dict(dropped=0), rx=dict(dropped=0)))
            stack.enter_context(patch.object(native.subprocess, 'check_output', return_value=json.dumps([link]).encode()))
            if failure == 'snapshot':
                stack.enter_context(patch.object(NativeIpv4State, 'snapshot', side_effect=OSError(errno.ENOSPC, 'injected evidence failure')))
            elif failure == 'close':
                close = NativeIpv4State.close

                def closed_then_failed(collector):
                    close(collector)
                    raise OSError(errno.EIO, 'injected close failure')

                stack.enter_context(patch.object(NativeIpv4State, 'close', closed_then_failed))
            with redirect_stdout(io.StringIO()) as output:
                self.assertFalse(native.child('failure-diagnostic', target, False, False))
            (target / 'observer-output.log').write_text(output.getvalue())
            launched.assert_called_once()
        receipt = json.loads((target / 'receipt.json').read_text())
        self.assertEqual(receipt['error'], 'RuntimeError: fragment client exited 1')
        self.assertEqual(receipt['returncode'], 1)
        self.assertFalse(receipt['passed'])
        state = receipt['native_kernel_state']
        if failure in ('none', 'capture'):
            self.assertTrue(state['complete'])
            rows = [json.loads(line) for line in (target / state['path']).read_text().splitlines()]
            self.assertIn('before client and capture shutdown', [row['reason'] for row in rows])
            self.assertIn('after capture and interface statistics', [row['reason'] for row in rows])
        else:
            self.assertFalse(state['complete'])
            self.assertTrue(receipt['native_kernel_state_errors'])

    def test_capture_shutdown_failure_retains_lane_and_original_client_failure(self):
        self.failed_child('capture')
        receipt = json.loads((DIRECTORY / 'failed-child-capture/receipt.json').read_text())
        self.assertEqual(receipt['capture_statistics'], [])
        self.assertEqual([row['lane'] for row in receipt['capture_finalization']], [0, 1])
        self.assertTrue(all(row['statistics'] is None and
                            row['error'] == 'RuntimeError: injected capture shutdown failure'
                            for row in receipt['capture_finalization']))

    def test_original_client_failure_keeps_counter_evidence(self):
        self.failed_child('none')

    def test_failed_snapshot_cannot_hide_original_client_failure(self):
        self.failed_child('snapshot')

    def test_failed_close_cannot_hide_original_client_failure(self):
        self.failed_child('close')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, default=DIRECTORY)
    args, rest = parser.parse_known_args()
    DIRECTORY = args.directory.resolve()
    if DIRECTORY == (ROOT / 'build').resolve() or not DIRECTORY.is_relative_to((ROOT / 'build').resolve()):
        parser.error('diagnostic evidence needs a dedicated directory beneath build/')
    unittest.main(argv=[sys.argv[0], *rest])

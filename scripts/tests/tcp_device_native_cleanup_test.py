# SPDX-License-Identifier: GPL-3.0-or-later
"""An actual peer failure must stop the owned native C client and namespace wrapper."""
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_fault_peer import check


def live(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z'
    except FileNotFoundError:
        return False


def worker(scratch, output):
    import tcp_device.native as native
    # Adopt the deliberately paused grandchild so the test can reap it after
    # checking the fixture's real cleanup path. No host-wide setting changes.
    check(ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0, 'private cleanup test becomes a child subreaper')
    owned = {}

    def failed_peer(process, *args, **kwargs):
        owned['wrapper_pid'] = process.pid
        began = time.monotonic()
        while time.monotonic() - began < 15:
            children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
            for child in children:
                try:
                    if Path(f'/proc/{child}/exe').resolve().name == 'tcp-device-native':
                        owned['C_child_pid'] = int(child)
                        owned['C_child_alive_before_failure'] = live(int(child))
                        # Prevent the C client's own timeout from masking a
                        # failure to stop its process group. This is a cleanup
                        # check, separate from all TCP timing observations.
                        os.kill(int(child), signal.SIGSTOP)
                        raise ValueError('injected peer failure after actual C client starts')
                except FileNotFoundError:
                    pass
            time.sleep(.005)
        raise RuntimeError('actual C child did not start')

    native.exercise = failed_peer
    try:
        native.namespace(scratch, 'native', 0, output)
    except SystemExit as error:
        owned['namespace_exit_status'] = error.code
    try:
        deadline = time.monotonic() + 3
        while live(owned['C_child_pid']) and time.monotonic() < deadline:
            time.sleep(.005)
        owned['C_child_alive_after_cleanup'] = live(owned['C_child_pid'])
        owned['passed'] = (owned['namespace_exit_status'] == 1 and owned['C_child_alive_before_failure'] and
                           not owned['C_child_alive_after_cleanup'])
    finally:
        if 'wrapper_pid' in owned:
            try:
                os.killpg(owned['wrapper_pid'], signal.SIGKILL)
            except ProcessLookupError:
                pass
        if 'C_child_pid' in owned:
            began = time.monotonic()
            while time.monotonic() - began < 3:
                try:
                    reaped, _ = os.waitpid(owned['C_child_pid'], os.WNOHANG)
                    if reaped:
                        break
                except ChildProcessError:
                    break
                time.sleep(.005)
            owned['test_cleanup_finished'] = not live(owned['C_child_pid'])
        (output / 'result.json').write_text(json.dumps(owned, indent=2) + '\n')
    check(owned['passed'] and owned['test_cleanup_finished'], 'real peer failure leaves no running owned C child')


def main():
    subprocess.run(['make', 'build/tcp-device-native'], cwd=ROOT, check=True)
    output = ROOT / 'build/tcp-device/cleanup-test'
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='axiom64-device-cleanup-') as temporary:
        scratch = Path(temporary)
        (scratch / 'parent-netns').write_text(os.readlink('/proc/self/ns/net'))
        with (output / 'worker.log').open('wb') as log:
            actual = subprocess.run(['unshare', '--net', sys.executable, __file__, '--worker',
                str(scratch), str(output)], stdout=log, stderr=subprocess.STDOUT, timeout=45)
    check(actual.returncode == 0, 'actual native cleanup failure probe succeeds')
    print('TCP_DEVICE_NATIVE_CLEANUP_PASS actual_C_child_started=1 owned_group_stopped=1')


if __name__ == '__main__':
    if '--worker' in sys.argv:
        worker(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        main()

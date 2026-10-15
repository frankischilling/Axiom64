# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain actual working-disk bytes when the evidence destination rejects copying."""
from pathlib import Path
import os
import signal
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from account_management_ext2 import execute, working_disk
from fetch import ROOT


def interrupted_worker(directory):
    marker = directory / 'worker.pid'
    program = ('import os,sys,time; from pathlib import Path; '
               'Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)')
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    worker = None
    sender_errors = []

    def interrupt():
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        if marker.exists():
            os.kill(os.getpid(), signal.SIGINT)
        else:
            sender_errors.append('owned worker did not start')

    sender = threading.Thread(target=interrupt)
    try:
        sender.start()
        interrupted = False
        try:
            execute([sys.executable, '-c', program, str(marker)], directory / 'worker.log')
        except KeyboardInterrupt:
            interrupted = True
        sender.join(timeout=4)
        assert not sender.is_alive() and not sender_errors and interrupted
        worker = int(marker.read_text())
        assert not Path('/proc/' + str(worker)).exists(), 'interrupted observation left its actual child running'
    finally:
        sender.join(timeout=4)
        signal.signal(signal.SIGINT, previous)
        if marker.exists():
            worker = int(marker.read_text())
            if Path('/proc/' + str(worker)).exists():
                assert os.getpgid(worker) == worker
                os.killpg(worker, signal.SIGKILL)
            try:
                os.waitpid(worker, 0)
            except ChildProcessError:
                pass


def main():
    (ROOT / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='management-retention-', dir=ROOT / 'build') as temporary:
        directory = Path(temporary)
        interrupted_worker(directory)
        completed = directory / 'completed.raw'
        completed.write_bytes(b'initial complete fixture\n')
        with working_disk(completed) as device:
            device.write_bytes(b'complete actual device fixture\n')
        assert completed.read_bytes() == b'complete actual device fixture\n' and not device.exists()
        try:
            with working_disk(completed) as device:
                device.write_bytes(b'failed actual device fixture\n')
                raise RuntimeError('owned observer failure')
        except RuntimeError as error:
            assert str(error) == 'owned observer failure'
        assert completed.read_bytes() == b'failed actual device fixture\n' and not device.exists()
        retained = directory / 'disk.raw'
        retained.write_bytes(b'original owned fixture\n')
        working = None
        try:
            with working_disk(retained) as working:
                working.write_bytes(b'actual changed device fixture\n')
                retained.rename(directory / 'original.raw')
                retained.mkdir()
        except (OSError, AssertionError):
            pass
        else:
            raise AssertionError('replaced evidence destination was accepted')
        assert working and working.exists(), 'retention failure discarded the actual device disk'
        assert working.read_bytes() == b'actual changed device fixture\n'
        assert retained.is_dir() and (directory / 'original.raw').read_bytes() == b'original owned fixture\n'
        assert working.parent.resolve().parent == Path('/tmp') and working.parent.name.startswith('axiom64-management-disk-')
        working.unlink()
        working.parent.rmdir()
    print('ACCOUNT_MANAGEMENT_STORAGE_PASS interrupted_child_reaped=1 completed_copy=1 observer_failure_copy=1 rejected_copy_preserved=1')


if __name__ == '__main__':
    main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Cancellation must stop the actual native client's complete process group."""
from pathlib import Path
import json
import os
import signal
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from path_descriptor_test import execute


def main():
    with tempfile.TemporaryDirectory(prefix='path-descriptor-cancellation-', dir=ROOT / 'build') as name:
        directory = Path(name)
        marker = directory / 'worker.json'
        program = ('import json,os,subprocess,sys,time; from pathlib import Path; '
                   'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
                   'Path(sys.argv[1]).write_text(json.dumps([os.getpid(),child.pid])); time.sleep(30)')
        errors = []

        def interrupt():
            deadline = time.monotonic() + 3
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            if marker.exists():
                os.kill(os.getpid(), signal.SIGINT)
            else:
                errors.append('actual worker did not start')

        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        sender = threading.Thread(target=interrupt)
        interrupted = False
        try:
            sender.start()
            try:
                execute([sys.executable, '-c', program, str(marker)], directory, True)
            except KeyboardInterrupt:
                interrupted = True
            sender.join(timeout=4)
            assert not sender.is_alive() and not errors and interrupted
            parent, child = json.loads(marker.read_text())
            assert not Path('/proc/' + str(parent)).exists(), 'native parent was not reaped'
            status = Path('/proc/' + str(child) + '/status')
            assert not status.exists() or 'State:\tZ' in status.read_text(), 'ordinary child remains live'
            assert (directory / 'execution.log').is_file()
        finally:
            sender.join(timeout=4)
            signal.signal(signal.SIGINT, previous)
            if marker.exists():
                parent, child = json.loads(marker.read_text())
                if Path('/proc/' + str(child)).exists() and os.getpgid(child) == parent:
                    os.killpg(parent, signal.SIGKILL)
    print('PATH_DESCRIPTOR_STORAGE_PASS parent_reaped=1 ordinary_child_stopped=1 log_retained=1')


if __name__ == '__main__':
    main()

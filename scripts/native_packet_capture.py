# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep burst capture independent of the Python Ethernet workload validator."""
from multiprocessing import Pipe
from multiprocessing.connection import Connection
from pathlib import Path
import json
import subprocess
import sys
import time

from tcp_fault_native import Capture as ThreadCapture
from tcp_fault_peer import check


def worker(connection, interface, path):
    capture = None
    try:
        capture = ThreadCapture(interface, path, defer_receipts=True)
        connection.send(('ready', None))
        pending = None
        while True:
            if pending is None or connection.poll(.002):
                command, value = connection.recv()
                if command == 'close':
                    closing = capture
                    capture = None
                    statistics = closing.close()
                    connection.send(('closed', statistics))
                    break
                check(command == 'watch' and pending is None, 'one isolated pending packet observation')
                pending = capture.watch(value)
                connection.send(('watch-ready', None))
            if pending is not None:
                observed = pending()
                if observed is not None:
                    connection.send(('observed', observed))
                    pending = None
    except BaseException as error:
        try:
            connection.send(('error', type(error).__name__ + ': ' + str(error)))
        except (BrokenPipeError, EOFError, OSError):
            pass
        raise
    finally:
        if capture is not None:
            capture.close()
        connection.close()


class Capture:
    def __init__(self, interface, path):
        self.connection, remote = Pipe()
        self.path = Path(path)
        self.process_path = self.path.with_suffix('.reader-process.json')
        self.started = time.monotonic_ns()
        self.waiting = False
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--worker',
                   str(remote.fileno()), interface, str(self.path)]
        with self.path.with_suffix('.reader.log').open('xb') as log:
            try:
                self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log,
                    stderr=subprocess.STDOUT, pass_fds=(remote.fileno(),))
            except BaseException:
                self.connection.close()
                raise
            finally:
                remote.close()
        self.command = command
        try:
            self.record('running')
            self.receive('ready', 5)
        except BaseException:
            self.stop()
            raise

    def record(self, status):
        self.process_path.write_text(json.dumps(dict(pid=self.process.pid, status=status,
            command=self.command, returncode=self.process.poll(),
            elapsed_ns=time.monotonic_ns() - self.started), indent=2))

    def receive(self, expected, timeout):
        check(self.connection.poll(timeout), 'isolated packet monitor coordination deadline')
        tag, value = self.connection.recv()
        check(tag == expected, f'isolated packet monitor {expected}: {tag} {value if tag == "error" else ""}')
        return value

    def watch(self, frame):
        check(not self.waiting and self.process.poll() is None, 'one live isolated packet watch')
        self.connection.send(('watch', bytes(frame)))
        self.receive('watch-ready', 2)
        self.waiting = True
        stamp = None

        def observed():
            nonlocal stamp
            if stamp is not None:
                return stamp
            check(self.process.poll() is None, 'isolated packet monitor remains healthy')
            if not self.connection.poll():
                return None
            stamp = self.receive('observed', 0)
            self.waiting = False
            return stamp
        return observed

    def observe_injection(self, frame, send, timeout=2):
        observed = self.watch(frame)
        check(send(frame) == len(frame), 'complete independently observed injection')
        check(self.connection.poll(timeout), 'independent capture observes the injected frame within its deadline')
        value = observed()
        check(value is not None, 'original isolated packet receipt')
        return value

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1)
        self.connection.close()
        self.record('completed')

    def close(self):
        try:
            self.connection.send(('close', None))
            deadline = time.monotonic() + 5
            while True:
                check(self.connection.poll(max(0, deadline - time.monotonic())),
                      'isolated packet monitor final serialization deadline')
                tag, value = self.connection.recv()
                if tag == 'observed':
                    self.waiting = False
                    continue
                check(tag == 'closed', f'isolated packet monitor close: {tag} {value if tag == "error" else ""}')
                break
            self.process.wait(timeout=1)
            check(self.process.returncode == 0 and value['receipt_serialization_deferred'] is True,
                  'completed isolated bounded native capture')
            value['isolated_reader_process'] = dict(pid=self.process.pid, status='completed', returncode=0)
            return value
        finally:
            self.stop()


if __name__ == '__main__':
    check(len(sys.argv) == 5 and sys.argv[1] == '--worker', 'explicit isolated packet monitor invocation')
    worker(Connection(int(sys.argv[2])), sys.argv[3], Path(sys.argv[4]))

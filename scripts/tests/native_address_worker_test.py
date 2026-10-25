# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual native CPU-mask ownership, exit propagation and cancellation."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
MASK = Path('/sys/devices/virtual/workqueue/cpumask')
CHILD = """import json,os,sys,time
from pathlib import Path
output=Path(sys.argv[1])
temporary=output.with_suffix('.tmp')
temporary.write_text(json.dumps(dict(pid=os.getpid(), affinity=sorted(os.sched_getaffinity(0)),
    worker_mask=Path('/sys/devices/virtual/workqueue/cpumask').read_text())))
temporary.replace(output)
if sys.argv[2]=='hold': time.sleep(30)
else: raise SystemExit(int(sys.argv[2]))
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT/'build/native-address-worker-tests')
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to(ROOT/'build'):
        raise ValueError('worker controls require bounded build output')
    directory.mkdir(parents=True, exist_ok=False)
    if os.geteuid():
        raise ValueError('actual native worker controls need root on a dedicated host')
    original = MASK.read_text()
    affinity = os.sched_getaffinity(0)
    results = []
    def command(name, status):
        return [sys.executable, '-B', str(ROOT/'scripts/native_address_worker.py'),
            '--receipt', str(directory/(name+'.json')), '--', sys.executable, '-c', CHILD,
            str(directory/(name+'-child.json')), str(status)]
    def restored(name):
        receipt = json.loads((directory/(name+'.json')).read_text())
        assert receipt['original_worker_mask_restored']
        assert receipt['original_process_affinity_restored']
        assert MASK.read_text() == original and os.sched_getaffinity(0) == affinity
        observed = json.loads((directory/(name+'-child.json')).read_text())
        assert observed['affinity'] == [receipt['selected_CPU']]
        assert int(observed['worker_mask'].strip().replace(',', ''), 16) == 1 << receipt['selected_CPU']
        return receipt, observed
    for name, expected in (('success',0), ('failure',7)):
        with (directory/(name+'.log')).open('xb') as log:
            done = subprocess.run(command(name,expected),stdout=log,stderr=subprocess.STDOUT,timeout=20)
        assert done.returncode == expected
        receipt, observed = restored(name)
        assert receipt['command_returncode'] == expected and receipt['passed'] == (expected == 0)
        results.append(dict(case=name,returncode=expected,restored=True))
    for name, number in (('terminate',signal.SIGTERM), ('interrupt',signal.SIGINT)):
        with (directory/(name+'.log')).open('xb') as log:
            process = subprocess.Popen(command(name,'hold'),stdout=log,stderr=subprocess.STDOUT)
            try:
                began = time.monotonic()
                ready = directory/(name+'-child.json')
                while not ready.exists():
                    assert process.poll() is None and time.monotonic()-began < 10
                    time.sleep(.02)
                observed = json.loads(ready.read_text())
                if name == 'terminate':
                    held = MASK.read_text()
                    with (directory/'busy.log').open('xb') as other_log:
                        busy = subprocess.run(command('busy',0),stdout=other_log,stderr=subprocess.STDOUT,timeout=10)
                    blocked = json.loads((directory/'busy.json').read_text())
                    assert busy.returncode == 1 and not blocked['passed']
                    assert any('BlockingIOError' in value for value in blocked['errors'])
                    assert MASK.read_text() == held
                    results.append(dict(case='busy-owner',returncode=1,other_mask_preserved=True))
                process.send_signal(number)
                assert process.wait(timeout=15) == 128+number
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        receipt, observed = restored(name)
        assert not (Path('/proc')/str(observed['pid'])).exists()
        results.append(dict(case=name,returncode=128+number,restored=True,owned_child_retired=True))
    assert len(results)==5
    (directory/'results.json').write_text(json.dumps(dict(passed=True,actual_kernel_controls=results),indent=2)+'\n')
    print('NATIVE_ADDRESS_WORKER_CONTROLS_PASS cases=5 actual_masks_exit_signal_and_lock_ownership',flush=True)


if __name__ == '__main__':
    main()

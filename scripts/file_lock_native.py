"""Compare the common file-lock contract with real Linux descriptions."""
import json
import os
import platform
import re
import subprocess
import tempfile
from pathlib import Path
from fetch import ROOT

MARKERS = ['FILE_LOCK_MODES_PASS conversion_advisory_errors',
           'FILE_LOCK_INODE_PASS hardlink_symlink_rename_unlink_directory',
           'FILE_LOCK_INHERITANCE_PASS fork_exec_cloexec_last_close',
           'FILE_LOCK_RETAINED_WAIT_PASS cycles=48 close_dup2_nonblock',
           'FILE_LOCK_SIGNALS_PASS interrupted_restart_fd_lookup',
           'FILE_LOCK_STOP_PASS fresh_lookup_after_continue',
           'FILE_LOCK_TEARDOWN_PASS exit_group_kill_exec',
           'FILE_LOCK_CONTENTION_PASS processes=8 updates=256 yield_while_locked']


def run():
    subprocess.run(['make', 'build/file-lock-native', 'build/file-lock-static',
                    'build/file-lock-dynamic'], cwd=ROOT, check=True)
    results = []
    with tempfile.TemporaryDirectory(prefix='axiom-file-lock-native-') as scratch:
        for label, program, linkage in [('gnu', 'file-lock-native', 'gnu'),
                                        ('musl-static', 'file-lock-static', 'static'),
                                        ('musl-dynamic', 'file-lock-dynamic', 'dynamic')]:
            log = ROOT / 'build' / f'file-lock-native-{label}.log'
            environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1')
            with log.open('wb') as output:
                completed = subprocess.run([str(ROOT / 'build' / program), str(Path(scratch) / label)],
                    cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT, timeout=30)
            text = log.read_text(errors='replace')
            trace = re.findall(r'FILE_LOCK_TRACE_PASS operations=4096 digest=([0-9a-f]{8})', text)
            missing = [marker for marker in MARKERS + [f'FILE_LOCK_TESTS_PASS linkage={linkage}']
                       if text.count(marker) != 1]
            passed = completed.returncode == 0 and not missing and len(trace) == 1 and not any(
                marker in text for marker in ['FILE_LOCK_FAIL', 'AddressSanitizer', 'runtime error:'])
            result = dict(program=program, linkage=linkage, returncode=completed.returncode,
                          missing=missing, trace=trace[0] if len(trace) == 1 else None,
                          passed=passed, log=log.name)
            results.append(result)
            print(json.dumps(result), flush=True)
            if not passed:
                raise RuntimeError(text[-2500:])
    if len({result['trace'] for result in results}) != 1:
        raise RuntimeError('native GNU and musl lock traces differ')
    result = dict(kernel=platform.release(), programs=results, trace=results[0]['trace'], passed=True)
    (ROOT / 'build/file-lock-native-results.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    run()

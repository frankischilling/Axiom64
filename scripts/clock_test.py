"""Compare guest elapsed clocks and deadlines with independently timed storage flushes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import tempfile
import time
from fetch import ROOT
from ext2_test import create_volume
from network_test import fixture


def run(firmware, transport, counter, delay, timeout, seed, scratch):
    label = f'clock-{firmware}-{transport}-{counter}-delay{delay}'
    log, trace = ROOT / 'build' / (label + '.log'), ROOT / 'build' / (label + '.trace')
    trace.unlink(missing_ok=True)
    disk, socket = scratch / 'volume.raw', scratch / 'nbd.sock'
    socket.unlink(missing_ok=True)
    shutil.copyfile(seed, disk)
    seed_hash = hashlib.sha256(seed.read_bytes()).hexdigest()
    if hashlib.sha256(disk.read_bytes()).hexdigest() != seed_hash:
        raise RuntimeError('clock fixture copy differs from the seed')
    with (ROOT / 'build' / (label + '-backend.log')).open('wb') as errors:
        backend = subprocess.Popen(['nbdkit', '-f', '--exit-with-parent', '-U', str(socket),
            'python', str(ROOT / 'scripts/delayed_block.py'), f'disk={disk}',
            f'delay={delay}', f'trace={trace}'], stdout=errors, stderr=errors)
    process = None
    started = time.monotonic()
    timed_out = False
    error = None
    try:
        until = started + 5
        while not socket.exists():
            if backend.poll() is not None or time.monotonic() > until:
                raise RuntimeError('clock fixture backend did not start')
            time.sleep(.02)
        command = ['qemu-system-x86_64', '-machine', 'pc,hpet=' + ('off' if counter == 'tsc' else 'on'),
            '-cpu', 'max', '-m', '512M', '-cdrom', str(ROOT / 'build/axiom64-clock.iso'),
            '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-nic', 'none', '-no-reboot',
            '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-blockdev',
            f'driver=nbd,node-name=clock,server.type=unix,server.path={socket}',
            '-device', 'virtio-blk-pci,drive=clock,addr=5,' +
            ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')]
        if counter == 'hpet-limit':
            command += ['-global', 'hpet.timers=32']
        if firmware == 'uefi':
            variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
            shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                        '-drive', f'if=pflash,format=raw,file={variables}']
        with log.open('wb') as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                process.wait()
    except Exception as failure:
        error = str(failure)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        backend.terminate()
        try:
            backend.wait(timeout=2)
        except subprocess.TimeoutExpired:
            backend.kill()
            backend.wait()
    text = log.read_text(errors='replace') if log.exists() else ''
    events = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
    durations = [event['seconds'] for event in events if event['event'] == 'flush_end']
    readings = re.findall(r'CLOCK_ELAPSED stage=(\S+) before=(\d+) after=(\d+) elapsed_ns=(\d+)', text)
    elapsed = {stage: int(interval) for stage, _, _, interval in readings}
    deadline = re.search(r'CLOCK_DEADLINE alarm=(\d) child_ready=(\d)', text)
    selected = 'Clock: HPET 64-bit counter' if counter == 'hpet' else 'Clock: calibrated TSC'
    missing = [marker for marker in [selected, 'CLOCK_ELAPSED_TESTS_PASS',
               'AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0'] if marker not in text]
    violations = []
    if len(readings) != 4 or set(elapsed) != {'sleep-before', 'mount', 'fsync', 'sleep-after'}:
        violations.append('incomplete guest clock readings')
    elif any(int(after) < int(before) or int(after) - int(before) != int(interval)
             for _, before, after, interval in readings):
        violations.append('inconsistent/backward guest readings')
    else:
        if any(not 100000000 <= elapsed[stage] <= 500000000
               for stage in ['sleep-before', 'sleep-after']):
            violations.append('ordinary sleep clock interval')
        if not durations or len(durations) != 7:
            violations.append('expected seven independently timed flushes')
        elif delay == 3:
            reference = statistics.median(durations)
            if any(duration < 2.9 for duration in durations):
                violations.append('backend did not delay every flush')
            if any(not .9 * reference <= elapsed[stage] / 1e9 <= 1.1 * reference + .15
                   for stage in ['mount', 'fsync']):
                violations.append('guest lost or mis-scaled the delayed flush interval')
            if not deadline or deadline.groups() != ('1', '1'):
                violations.append('absolute futex/interval timer deadlines did not expire across storage')
        elif elapsed['fsync'] > 1000000000:
            violations.append('zero-delay flush clock interval')
    if not deadline:
        violations.append('missing deadline observation')
    result = dict(firmware=firmware, transport=transport, counter=counter, delay=delay,
        seed_sha256=seed_hash, returncode=process.returncode if process else None,
        timed_out=timed_out, error=error, missing=missing, violations=violations,
        elapsed_ns=elapsed, flush_seconds=durations,
        alarm=int(deadline[1]) if deadline else None,
        child_ready=int(deadline[2]) if deadline else None,
        seconds=round(time.monotonic() - started, 3), log=log.name, trace=trace.name,
        passed=not timed_out and error is None and process is not None and process.returncode == 1
               and not missing and not violations and 'PANIC:' not in text and 'Page fault' not in text)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-2500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--counter', choices=['hpet', 'tsc', 'hpet-limit', 'both', 'all'], default='all')
    parser.add_argument('--delay', choices=['0', '3', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    fixture(program='clock-elapsed-tests', script='userspace/tests/time/elapsed.sh')
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'axiom64-clock.iso'], cwd=ROOT, check=True)
    result = dict(seed_sha256=None, seed_unchanged=False, boots=[])
    path = ROOT / 'build/clock-results.json'
    with tempfile.TemporaryDirectory(prefix='axiom64-clock-') as temporary:
        scratch = Path(temporary)
        seed = scratch / 'seed.raw'
        create_volume(seed)
        result['seed_sha256'] = hashlib.sha256(seed.read_bytes()).hexdigest()
        for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
            for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
                counters = ['hpet', 'tsc', 'hpet-limit'] if args.counter == 'all' else (
                    ['hpet', 'tsc'] if args.counter == 'both' else [args.counter])
                for counter in counters:
                    for delay in [0, 3] if args.delay == 'both' else [int(args.delay)]:
                        boot = run(firmware, transport, counter, delay, args.timeout, seed, scratch)
                        result['boots'].append(boot)
                        result['seed_unchanged'] = hashlib.sha256(seed.read_bytes()).hexdigest() == result['seed_sha256']
                        path.write_text(json.dumps(result, indent=2) + '\n')
                        if not boot['passed'] or not result['seed_unchanged']:
                            raise SystemExit('Elapsed clock/storage deadline check failed')


if __name__ == '__main__':
    main()

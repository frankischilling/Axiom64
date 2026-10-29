#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check calendar clocks and real elapsed deadlines against native Linux and QEMU RTCs."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time

from build_musl import loader
from clock_wall_observer import calendar, check_hardware
from fetch import ROOT
from random_administration_test import checked_run, copy_executable, fingerprint, snapshot
from random_seed_test import image
from random_snapshot_test import QMP

DATES = {'host': None, 'epoch': '1970-01-01T00:00:00',
         'leap': '2000-02-29T12:00:00', '2038': '2038-01-19T03:14:08',
         '2100': '2100-03-01T23:59:58'}
# QEMU 8.2.2 keeps a signed 32-bit custom-date offset for clock=host. Its
# clock=rt uses the requested epoch plus unscaled host elapsed time instead;
# neither option accelerates the guest or the deadline observations.


def firmware_date(date, firmware):
    if date is None or firmware != 'uefi':
        return date
    value = datetime.fromisoformat(date)
    # The tested OVMF RTC driver reconstructs a two-digit year in 2000–2099
    # before writing its century register. This is an explicit firmware
    # limitation, independently checked through QEMU's actual RTC property.
    return value.replace(year=2000+value.year % 100).isoformat()




def guest_run(command, case, date, expected_date):
    log = case / 'guest.log'
    row = dict(timed_out=False, passed=False)
    started = time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix='axiom64-wall-qmp-') as temporary:
        socket = Path(temporary) / 'qmp.sock'
        command = [*command, '-S', '-qmp', f'unix:{socket},server=on,wait=off']
        row['command'] = command
        process = monitor = None
        try:
            with log.open('wb') as stream:
                before = time.time_ns()
                process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                           stdout=stream, stderr=subprocess.STDOUT)
                monitor = QMP(socket, process, case / 'qmp.jsonl', 5)
                initial_before = time.time_ns()
                initial_monotonic_before = time.monotonic_ns()
                initial = monitor.command('qom-get', dict(path='/machine', property='rtc-time'))
                initial_monotonic_after = time.monotonic_ns()
                initial_after = time.time_ns()
                row.update(initial_hardware_calendar=initial,
                           initial_hardware_interval_ns=[initial_before, initial_after],
                           initial_hardware_monotonic_interval_ns=[initial_monotonic_before, initial_monotonic_after])
                if date is not None:
                    expected = int(datetime.fromisoformat(date).replace(tzinfo=timezone.utc).timestamp())
                    if not expected <= calendar(initial) <= expected+5:
                        raise RuntimeError('the initial QEMU RTC differs from its requested date')
                monitor.command('cont')
                deadline = time.monotonic()+30

                def wait(marker):
                    while marker not in log.read_bytes():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError('the calendar client did not reach hardware observation')
                        time.sleep(.01)

                wait(b'Clock: RTC UTC seconds=')
                reference_before = time.monotonic_ns()
                reference = monitor.command('qom-get', dict(path='/machine', property='rtc-time'))
                reference_after = time.monotonic_ns()
                events = [json.loads(line)['value'] for line in (case/'qmp.jsonl').read_text().splitlines()
                          if json.loads(line)['direction'] == 'receive']
                row.update(reference_hardware_calendar=reference,
                           reference_hardware_monotonic_interval_ns=[reference_before, reference_after],
                           reference_firmware_changes=[event for event in events if event.get('event') == 'RTC_CHANGE'])
                wait(b'CLOCK_WALL_RTC_OBSERVER')
                sample_before = time.time_ns()
                sample_monotonic_before = time.monotonic_ns()
                sample = monitor.command('qom-get', dict(path='/machine', property='rtc-time'))
                sample_monotonic_after = time.monotonic_ns()
                sample_after = time.time_ns()
                row.update(hardware_calendar=sample, hardware_interval_ns=[sample_before, sample_after],
                           hardware_monotonic_interval_ns=[sample_monotonic_before, sample_monotonic_after])
                process.wait(timeout=max(.01, deadline-time.monotonic()))
                after = time.time_ns()
            text = log.read_text()
            row.update(returncode=process.returncode, elapsed_ns=time.monotonic_ns()-started,
                       log=log.name, log_input=fingerprint(log), requested_date=date,
                       firmware_expected_date=expected_date,
                       firmware_changed_century=date != expected_date)
            check(row, text, before, after, expected_date)
            events = [json.loads(line)['value'] for line in (case/'qmp.jsonl').read_text().splitlines()
                      if json.loads(line)['direction'] == 'receive']
            check_hardware(row, before, expected_date, events)
            return row, text
        except BaseException as error:
            row.update(passed=False, error=repr(error))
            if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
                row['timed_out'] = True
            raise
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            if monitor:
                monitor.close()
            row.update(returncode=process.returncode if process else None,
                       elapsed_ns=time.monotonic_ns()-started)
            if log.exists():
                row['log_input'] = fingerprint(log)
            (case / 'process.json').write_text(json.dumps(row, indent=2)+'\n')


def check(row, text, before_ns, after_ns, date):
    observation = re.findall(r'^CLOCK_WALL_OBSERVATION seconds=(\d+) nanoseconds=(\d+) monotonic_ns=(\d+)$',
                             text, re.MULTILINE)
    if len(observation) != 1 or 'CLOCK_WALL_PASS ' not in text or 'CLOCK_WALL_FAIL ' in text:
        raise RuntimeError('the wall-clock probe did not complete once')
    fields = ('precise_first_s', 'precise_first_ns', 'timeval_s', 'timeval_us',
              'time_return_s', 'time_store_s', 'precise_last_s', 'precise_last_ns',
              'coarse_first_s', 'coarse_first_ns', 'coarse_last_s', 'coarse_last_ns')
    pattern = '^CLOCK_WALL_INTERFACES ' + ' '.join(name + r'=(-?\d+)' for name in fields) + '$'
    samples = re.findall(pattern, text, re.MULTILINE)
    if len(samples) != 1:
        raise RuntimeError('the wall interfaces lack one complete precise/coarse observation')
    interfaces = dict(zip(fields, map(int, samples[0])))
    first = (interfaces['precise_first_s'], interfaces['precise_first_ns'])
    last = (interfaces['precise_last_s'], interfaces['precise_last_ns'])
    coarse_first = (interfaces['coarse_first_s'], interfaces['coarse_first_ns'])
    coarse_last = (interfaces['coarse_last_s'], interfaces['coarse_last_ns'])
    if (any(not 0 <= sample[1] < 1_000_000_000 for sample in (first, last, coarse_first, coarse_last))
            or not 0 <= interfaces['timeval_us'] < 1_000_000
            or not first[0] <= interfaces['timeval_s'] <= last[0]
            or not coarse_first[0] <= interfaces['time_store_s'] <= coarse_last[0]
            or interfaces['time_return_s'] != interfaces['time_store_s']
            or coarse_first > coarse_last):
        raise RuntimeError('the wall interfaces differ from their actual precise/coarse brackets')
    seconds, nanoseconds, monotonic_ns = map(int, observation[0])
    if (seconds, nanoseconds) != last:
        raise RuntimeError('the calendar observation differs from its precise interface sample')
    actual = seconds * 1_000_000_000 + nanoseconds
    minimum = before_ns if date is None else int(datetime.fromisoformat(date).replace(
        tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    maximum = after_ns if date is None else minimum + after_ns - before_ns
    if not minimum - 1_000_000_000 <= actual <= maximum + 2_000_000_000:
        raise RuntimeError('the guest calendar is outside its independently observed RTC interval')
    if any(not minimum - 1_000_000_000 <= sample[0] * 1_000_000_000 + sample[1] <= maximum + 2_000_000_000
           for sample in (coarse_first, coarse_last)):
        raise RuntimeError('the coarse calendar is outside its independently observed RTC interval')
    if not 0 <= nanoseconds < 1_000_000_000:
        raise RuntimeError('the calendar fraction is invalid')
    row.update(interfaces=interfaces,
               observed=dict(seconds=seconds, nanoseconds=nanoseconds, monotonic_ns=monotonic_ns),
               host_interval_ns=[before_ns, after_ns], rtc_interval_ns=[minimum, maximum],
               calendar_tolerance_ns=[1_000_000_000, 2_000_000_000], passed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--linkage', choices=('native', 'static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--rtc', choices=tuple(DATES), nargs='+', default=list(DATES))
    parser.add_argument('--output', type=Path, default=ROOT / 'build/clock-wall-results')
    args = parser.parse_args()
    if args.linkage == 'native' and not args.native:
        parser.error('native libc requires --native')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    linkages = ('native', 'static', 'dynamic') if args.native and args.linkage == 'both' else (
        ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,))
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    *(f'build/{program}-{linkage}' for linkage in linkages for program in
                      (('clock-wall',) if args.native else
                       ('clock-wall', 'random', 'random-seed', 'random-seed-probe')))],
                   cwd=ROOT, check=True)
    inputs = snapshot(out)
    for name in ('scripts/clock_wall_test.py', 'scripts/clock_wall_observer.py', 'userspace/tests/time/wall.c',
                 'scripts/random_seed_test.py', 'scripts/image.py', 'scripts/random_snapshot_test.py'):
        inputs[name] = fingerprint(ROOT / name)
    (out / 'source-inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    results = []
    for linkage in linkages:
        client = ROOT / f'build/clock-wall-{linkage}'
        if args.native:
            case = out / linkage
            case.mkdir()
            copy_executable(client, case / 'clock-wall')
            command = [str(case / 'clock-wall')]
            if linkage == 'dynamic':
                command.insert(0, str(loader()))
            before = time.time_ns()
            row, text = checked_run(command, case / 'native.log', 10)
            after = time.time_ns()
            row.update(native=True, linkage=linkage, client=fingerprint(case / 'clock-wall'),
                       kernel=platform.uname()._asdict(), host_interval_ns=[before, after])
            try:
                check(row, text, before, after, None)
                if row['returncode'] != 0 or row['timed_out']:
                    raise RuntimeError('the native calendar client failed')
            except BaseException as error:
                row.update(passed=False, error=repr(error))
                raise
            finally:
                (case / 'process.json').write_text(json.dumps(row, indent=2)+'\n')
            results.append(row)
        else:
            folder = out / (linkage + '-image')
            folder.mkdir()
            iso = image(folder, linkage, 'clock-wall', command='/bin/clock-wall\necho CLOCK_WALL_RTC_OBSERVER\n/bin/busybox sleep 1',
                        extra_products={'bin/clock-wall': client})
            for firmware in ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,):
                for rtc in args.rtc:
                    case = out / f'{linkage}-{firmware}-{rtc}'
                    case.mkdir()
                    date = DATES[rtc]
                    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M',
                               '-nic', 'none', '-rtc', 'base=' + (date or 'utc') + ',clock=rt',
                               '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio', '-monitor', 'none',
                               '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
                    firmware_inputs = {}
                    if firmware == 'uefi':
                        variables = case / 'VARS.fd'
                        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                        firmware_inputs = {name: fingerprint(Path('/usr/share/OVMF') / name) for name in
                                           ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd')}
                        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                    '-drive', 'if=pflash,format=raw,file=' + str(variables)]
                    row, text = guest_run(command, case, date, firmware_date(date, firmware))
                    row.update(native=False, linkage=linkage, firmware=firmware, rtc=rtc,
                               image=fingerprint(iso), firmware_inputs=firmware_inputs)
                    try:
                        if row['returncode'] != 1 or row['timed_out'] or 'Clock: RTC UTC seconds=' not in text:
                            raise RuntimeError('the guest calendar client or RTC source failed')
                    except BaseException as error:
                        row.update(passed=False, error=repr(error))
                        raise
                    finally:
                        (case / 'result.json').write_text(json.dumps(row, indent=2)+'\n')
                    results.append(row)
                    (out / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
                    print(json.dumps(dict(case=case.name, passed=True, observed=row['observed'])), flush=True)
        (out / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
    if not results or inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('the wall-clock source changed or no comparison ran')


if __name__ == '__main__':
    main()

"""Boot real address updates and configuration ownership/recovery checks."""
import argparse
import json
import shutil
import subprocess
import time
from fetch import ROOT
from network_test import fixture


def run(firmware, transport, timeout):
    label = f'configuration-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(ROOT / 'build/axiom64-configuration.iso'), '-nic', 'none',
               '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-no-reboot',
               '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
               '-netdev', 'user,id=first,restrict=on',
               '-device', 'virtio-net-pci,netdev=first,addr=4,mac=52:54:00:12:34:10,' +
               ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on'),
               '-netdev', 'user,id=second,restrict=on',
               '-device', 'e1000,netdev=second,addr=5,mac=52:54:00:12:34:11']
    if firmware == 'uefi':
        variables = ROOT / 'build' / (label + '-OVMF_VARS.fd')
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', f'if=pflash,format=raw,file={variables}']
    started = time.monotonic()
    timed_out = False
    with log.open('wb') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
    text = log.read_text(errors='replace')
    names = ['ADDRESS_MESSAGES', 'ADDRESS_PRESSURE', 'REPLACEMENT_RECOVERY', 'MANUAL_PRESERVATION',
             'CORRUPT_JOURNAL', 'JOURNAL_FAILURE', 'INTENT_RECOVERY',
             'PROCESS_RECOVERY', 'ROLLBACK', 'TESTS']
    missing = [f'CONFIGURATION_{name}_PASS' for name in names if f'CONFIGURATION_{name}_PASS' not in text]
    missing += [name for name in ['AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0'] if name not in text]
    result = dict(firmware=firmware, transport=transport, returncode=process.returncode,
                  timed_out=timed_out, missing=missing, log=log.name,
                  seconds=round(time.monotonic() - started, 3),
                  passed=not timed_out and process.returncode == 1 and not missing and
                  'PANIC:' not in text and 'Page fault' not in text)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-2500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    fixture(program='configuration-tests', script='userspace/tests/net/configuration.sh')
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'axiom64-configuration.iso'], cwd=ROOT, check=True)
    results = []
    for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
        for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
            result = run(firmware, transport, args.timeout)
            results.append(result)
            (ROOT / 'build/configuration-results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not result['passed']:
                raise SystemExit('Configuration ownership/recovery check failed')


if __name__ == '__main__':
    main()

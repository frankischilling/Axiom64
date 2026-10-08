"""Run the DHCP codec, lease state, and saved-profile modules in Ring 3."""
import argparse
import json
import shutil
import subprocess
import time
from fetch import ROOT
from network_test import fixture

MARKERS = {
    'codec': ['PARAMETERS', 'OPTIONS', 'OVERLOAD_SEARCH', 'ROUTES', 'SEARCH_BOUNDARIES',
              'ENCODING', 'FRAME', 'ARP', 'MUTATIONS', 'TESTS'],
    'state': ['ACQUISITION', 'RETRANSMISSION', 'LEASES', 'TIMERS_PARAMETERS',
              'NAK_INSTALLATION', 'CONFLICTS', 'LIFECYCLE', 'OVERLAPPING_TIMERS',
              'DELAYED_COMPLETION_STOP', 'TESTS'],
    'profile': ['PARSING', 'ATOMIC_FILES', 'TESTS'],
}


def run(suite, firmware, transport, timeout):
    label = f'dhcp-modules-{suite}-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(ROOT / 'build' / f'axiom64-dhcp-{suite}.iso'), '-nic', 'none',
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
    required = [f'DHCP_{suite.upper()}_{name}_PASS' for name in MARKERS[suite]]
    required += ['AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0']
    missing = [name for name in required if name not in text]
    result = dict(suite=suite, firmware=firmware, transport=transport,
                  returncode=process.returncode, timed_out=timed_out, missing=missing,
                  log=log.name, seconds=round(time.monotonic() - started, 3),
                  passed=not timed_out and process.returncode == 1 and not missing and
                  'PANIC:' not in text and 'Page fault' not in text)
    print(json.dumps(result), flush=True)
    if not result['passed']:
        print(text[-3500:], flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=['all', *MARKERS], default='all')
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=60)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results = []
    for suite in MARKERS if args.suite == 'all' else [args.suite]:
        fixture(program=f'dhcp-{suite}-tests', script=f'userspace/tests/net/dhcp-{suite}.sh')
        subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                        '--output-name', f'axiom64-dhcp-{suite}.iso'], cwd=ROOT, check=True)
        for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
            for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
                result = run(suite, firmware, transport, args.timeout)
                results.append(result)
                (ROOT / 'build/dhcp-modules-results.json').write_text(json.dumps(results, indent=2) + '\n')
                if not result['passed']:
                    raise SystemExit('DHCP module check failed')


if __name__ == '__main__':
    main()

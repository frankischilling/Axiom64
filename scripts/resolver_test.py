"""Boot resolver metadata, manual preservation, and ownership recovery checks."""
import argparse
import json
import shutil
import subprocess
import time
from fetch import ROOT
from network_test import fixture

MARKERS = ['RESOLVER_MERGE_PASS', 'RESOLVER_LIMITS_PASS interfaces=8 search_line=255',
           'RESOLVER_MANUAL_PRESERVATION_PASS', 'RESOLVER_MANUAL_TAKEOVER_PASS',
           'RESOLVER_PROCESS_CORRUPT_RECOVERY_PASS cycles=70 semantic=20',
           'RESOLVER_PUBLICATION_FAILURE_PASS renames=3 syncs=6 rollback=1 link_sync=1',
           'RESOLVER_INTENT_RECOVERY_PASS phases=4 manual=1',
           'RESOLVER_PERMISSIONS_PASS umask=077 directory=0755 text=0644 record=0600',
           'RESOLVER_RESOURCE_RETRY_PASS', 'RESOLVER_TESTS_PASS']


def run(firmware, transport, timeout):
    label = f'resolver-{firmware}-{transport}'
    log = ROOT / 'build' / (label + '.log')
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '2G',
               '-cdrom', str(ROOT / 'build/axiom64-resolver.iso'), '-nic', 'none',
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
    missing = [marker for marker in MARKERS if marker not in text]
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
    fixture(program='resolver-tests', script='userspace/tests/net/resolver.sh')
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--output-name', 'axiom64-resolver.iso'], cwd=ROOT, check=True)
    results = []
    for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
        for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
            result = run(firmware, transport, args.timeout)
            results.append(result)
            (ROOT / 'build/resolver-results.json').write_text(json.dumps(results, indent=2) + '\n')
            if not result['passed']:
                raise SystemExit('Resolver ownership/recovery check failed')


if __name__ == '__main__':
    main()

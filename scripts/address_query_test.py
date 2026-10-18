"""Compare actual address withdrawal through the production getter on native Linux."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from build_musl import loader
from fetch import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside-namespace', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo to create an isolated network namespace')
    if not args.inside_namespace:
        subprocess.run(['make', '-j2', 'build/address-query-native', 'build/address-query-static',
                        'build/address-query-dynamic'], cwd=ROOT, check=True)
        subprocess.run(['unshare', '--net', '--fork', sys.executable, str(Path(__file__).resolve()),
                        '--inside-namespace'], cwd=ROOT, check=True, timeout=30)
        return
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    subprocess.run(['ip', 'link', 'add', 'query0', 'type', 'veth', 'peer', 'name', 'query-peer'], check=True)
    results = []
    for profile in ('native', 'static', 'dynamic'):
        binary = ROOT / 'build' / f'address-query-{profile}'
        interpreter = loader() if profile == 'dynamic' else None
        command = ([str(interpreter)] if interpreter else []) + [str(binary), 'query0', 'query-peer']
        log = ROOT / 'build' / f'address-query-native-{profile}.log'
        result = dict(profile=profile, command=command, log=log.name,
                      binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                      getter_sha256=hashlib.sha256(
                          (ROOT / 'userspace/net/dhcp/transport.cpp').read_bytes()).hexdigest(),
                      interpreter_sha256=hashlib.sha256(interpreter.read_bytes()).hexdigest()
                      if interpreter else None)
        with log.open('wb') as output:
            process = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=5)
        text = log.read_text(errors='replace')
        result.update(returncode=process.returncode, passed=process.returncode == 0 and
                      all(f'ADDRESS_QUERY_PASS interface={name} actual_withdrawal=1 '
                          'no_leaked_descriptors=1 real_errors_preserved=1' in text
                          for name in ('query0', 'query-peer')) and 'ADDRESS_QUERY_FAIL' not in text)
        results.append(result)
        (ROOT / 'build/address-query-native-results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(json.dumps(result), flush=True)
        if not result['passed']:
            print(text, flush=True)
            raise SystemExit('Native address withdrawal comparison failed')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Run IPv4 and failed-device contracts with both firmware and virtio transports."""
import json
import subprocess
import sys
from fetch import ROOT
from network_test import fixture
from ipv4_test import run


def main():
    results = []
    destination = ROOT / 'build/ipv4-results.json'
    try:
        for fault in [False, True]:
            fixture(program='ipv4-tests', script='userspace/tests/net/ipv4.sh',
                    environment={'AXIOM64_IP_FAULT': '1'} if fault else None)
            subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                            '--output-name', 'ipv4-test.iso'], cwd=ROOT, check=True)
            for transport in ['modern', 'legacy']:
                for firmware in ['bios', 'uefi']:
                    result = run(firmware, transport, 120, fault)
                    results.append(result)
                    destination.write_text(json.dumps(results, indent=2) + '\n')
                    if not result['passed']:
                        raise RuntimeError(f'IPv4 contract failed: {result["log"]}')
    finally:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(results, indent=2) + '\n')
    print(f'IPV4_MATRIX_PASS boots={len(results)}', flush=True)


if __name__ == '__main__':
    main()

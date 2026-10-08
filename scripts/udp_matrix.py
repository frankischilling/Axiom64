#!/usr/bin/env python3
"""Verify UDP sockets with both firmware, virtio transports, and device faults."""
import json
import subprocess
import sys
from fetch import ROOT
from network_test import fixture
from udp_test import run


def main():
    results = []
    destination = ROOT / 'build/udp-results.json'
    try:
        for fault in [False, True]:
            fixture(program='udp-tests', script='userspace/tests/net/udp.sh',
                    environment={'AXIOM64_UDP_FAULT': '1'} if fault else None)
            subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                            '--output-name', 'udp-test.iso'], cwd=ROOT, check=True)
            for transport in ['modern', 'legacy']:
                for firmware in ['bios', 'uefi']:
                    delay = 5 if fault and firmware == 'uefi' and transport == 'modern' else 0
                    result = run(firmware, transport, 90, fault, delay)
                    results.append(result)
                    destination.write_text(json.dumps(results, indent=2) + '\n')
                    if not result['passed']:
                        raise RuntimeError(f'UDP contract failed: {result["log"]}')
    finally:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(results, indent=2) + '\n')
    print(f'UDP_MATRIX_PASS boots={len(results)}', flush=True)


if __name__ == '__main__':
    main()

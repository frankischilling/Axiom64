#!/usr/bin/env python3
"""Verify UDP sockets across QEMU firmware, transports, and interrupt routes."""
import argparse
import json
import subprocess
import sys
from fetch import ROOT
from network_test import fixture
from udp_test import run
from udp_inputs import record, save_case


def main(directory=None):
    subprocess.run([sys.executable, 'scripts/tests/udp_peer_test.py'], cwd=ROOT, check=True)
    directory = directory or ROOT / 'build/udp-wire'
    directory.mkdir(parents=True, exist_ok=False)
    results = []
    destination = ROOT / 'build/udp-results.json'
    try:
        for fault in [False, True]:
            fixture(program='udp-tests', script='userspace/tests/net/udp.sh',
                    environment={'AXIOM64_UDP_FAULT': '1'} if fault else None)
            subprocess.run([sys.executable, 'scripts/image.py', '--test', '--suite', 'network',
                            '--output-name', 'udp-test.iso'], cwd=ROOT, check=True)
            phase = directory / ('fault' if fault else 'normal')
            record(phase, fault)
            for transport in ['modern', 'legacy']:
                for firmware in ['bios', 'uefi']:
                    delay = 5 if fault and firmware == 'uefi' and transport == 'modern' else 0
                    case = phase / (firmware + '-' + transport)
                    expected_irq = None if fault else 'msix' if transport == 'modern' else 'poll'
                    result = run(firmware, transport, 90, fault, delay,
                                 capture_directory=case, image=phase / 'image.iso',
                                 expected_irq=expected_irq)
                    save_case(result, case)
                    results.append(result)
                    destination.write_text(json.dumps(results, indent=2) + '\n')
                    if not result['passed']:
                        raise RuntimeError(f'UDP contract failed: {result["log"]}')
    finally:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(results, indent=2) + '\n')
        (directory / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(f'UDP_MATRIX_PASS boots={len(results)}', flush=True)


def test_interrupt_routes():
    # Keep each platform case in its own guest so firmware and IRQ mode cannot leak between cases.
    cases = (
        ('uefi', 'q35', 'msix', (), None),
        ('bios', 'pc', 'poll', ('--no-vectors',), None),
        ('bios', 'pc', 'poll', ('--force-pic',), None),
        ('bios', 'q35', 'msix', ('--e1000e',), 'udp-e1000e/bios'),
        ('uefi', 'q35', 'msix', ('--e1000e',), 'udp-e1000e/uefi'),
        ('uefi', 'q35', 'poll', ('--e1000e', '--force-pic'), 'udp-e1000e/uefi-pic'),
        ('bios', 'q35', 'msix', ('--intx', 'single'), 'udp-intx/bios'),
        ('uefi', 'q35', None, ('--intx', 'shared'), 'udp-intx/uefi-shared'),
        ('uefi', 'q35', 'poll', ('--intx', 'poll', '--force-pic'), 'udp-intx/uefi-pic'),
        ('bios', 'q35', 'msix', ('--intx', 'bridge'), 'udp-intx/bios-bridge'),
        ('uefi', 'q35', 'msix', ('--intx', 'bridge'), 'udp-intx/uefi-bridge'),
        ('bios', 'pc', 'msix', ('--intx', 'single'), 'udp-intx/pc-bios'),
        ('uefi', 'pc', 'msix', ('--intx', 'single'), 'udp-intx/pc-uefi'),
        ('bios', 'pc', 'msix', ('--intx', 'reprogram'), 'udp-intx/pc-bios-reprogram'),
        ('uefi', 'pc', 'msix', ('--intx', 'reprogram'), 'udp-intx/pc-uefi-reprogram'),
        ('uefi', 'pc', 'poll', ('--intx', 'poll', '--force-pic'), 'udp-intx/pc-uefi-pic'),
    )
    for firmware, machine, irq, options, capture in cases:
        command = [sys.executable, 'scripts/udp_test.py', '--firmware', firmware,
                   '--machine', machine, *options]
        if irq:
            command += ['--expected-irq', irq]
        if capture:
            command += ['--capture-directory', f'build/{capture}']
        subprocess.run(command, cwd=ROOT, check=True)
    print(f'UDP_INTERRUPT_ROUTES_PASS boots={len(cases)}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', action='store_true', help='run chipset and interrupt cases')
    if parser.parse_args().platform:
        test_interrupt_routes()
    else:
        main()

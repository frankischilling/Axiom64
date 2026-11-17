# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify isolated native Ethernet forwarding before a timed workload starts."""
import json
from pathlib import Path
import subprocess
import time


def prepare(directory):
    path = Path(directory) / 'native-link-ready.json'
    if path.exists():
        raise ValueError('native bridge startup requires a fresh receipt')
    began = time.monotonic_ns()
    deadline = time.monotonic() + 2
    receipt = dict(passed=False, begin_monotonic_ns=began, deadline_seconds=2,
                   workload_started=False, polls=0)
    try:
        names = [f'{prefix}{lane}' for lane in range(2) for prefix in ('eth', 'peer', 'bridge')]
        disabled = {scope: Path(f'/proc/sys/net/ipv6/conf/{scope}/disable_ipv6').read_text().strip()
                    for scope in ('all', 'default', *names)}
        receipt['disable_ipv6'] = disabled
        if any(value != '1' for value in disabled.values()):
            raise ValueError('native bridge startup keeps IPv6 disabled until the client enables it')
        for lane in range(2):
            subprocess.run(['ip', 'link', 'set', f'eth{lane}', 'up'], check=True, timeout=2)
        while True:
            rows = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show'], timeout=2))
            links = {row['ifname']: row for row in rows if row['ifname'] in names}
            receipt['polls'] += 1
            receipt.setdefault('initial_links', links)
            receipt['final_links'] = links
            ready = set(links) == set(names)
            for lane in range(2):
                for prefix in ('eth', 'peer', 'bridge'):
                    link = links.get(f'{prefix}{lane}', {})
                    ready &= {'UP', 'LOWER_UP'} <= set(link.get('flags', ()))
                    ready &= link.get('operstate') == 'UP'
                peer = links.get(f'peer{lane}', {})
                info = peer.get('linkinfo', {})
                ready &= peer.get('master') == f'bridge{lane}'
                ready &= info.get('info_slave_kind') == 'bridge'
                ready &= info.get('info_slave_data', {}).get('state') == 'forwarding'
            if time.monotonic() >= deadline:
                raise ValueError('native bridge forwarding did not become ready before the setup deadline')
            if ready:
                receipt['passed'] = True
                break
            time.sleep(.01)
    except BaseException as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        receipt['end_monotonic_ns'] = time.monotonic_ns()
        path.write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt

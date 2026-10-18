# SPDX-License-Identifier: GPL-3.0-or-later
"""Run full scoped native-netdevice and guest-PCI loss acceptance cohorts."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('native', 'guest'))
    parser.add_argument('--workers', type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    if args.mode == 'native':
        from tcp_device.native import run
    else:
        from tcp_device.guest import run
    rows = run(args.workers) if args.mode == 'guest' else run()
    directory = ROOT / 'build/tcp-device'
    save(directory / f'{args.mode}-results.json', rows)
    raise SystemExit(0 if rows and all(row['passed'] for row in rows) else 1)


if __name__ == '__main__':
    # These two internal entry points keep ownership of every namespace process explicit.
    if len(sys.argv) > 1 and sys.argv[1] in ('--client', '--namespace'):
        from tcp_device.native import client, namespace
        mode, scratch, linkage, affected, output = sys.argv[1:]
        (client if mode == '--client' else namespace)(Path(scratch), linkage, int(affected), Path(output))
    else:
        main()

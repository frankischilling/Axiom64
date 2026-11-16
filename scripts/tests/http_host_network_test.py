#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the actual host guard against finite address countdown and changed state."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from http_download.host_network import capture, verify, SECOND, FOREVER

OUTPUT = None


def observe(directory, parent):
    if os.readlink('/proc/self/ns/net') == parent:
        raise RuntimeError('host guard control requires its own network namespace')
    subprocess.run(['ip', 'link', 'add', 'guard0', 'type', 'dummy'], check=True)
    subprocess.run(['ip', 'address', 'add', '192.0.2.2/24', 'dev', 'guard0',
                    'valid_lft', '60', 'preferred_lft', '30'], check=True)
    subprocess.run(['ip', 'address', 'add', '192.0.2.3/24', 'dev', 'guard0'], check=True)
    subprocess.run(['ip', '-6', 'address', 'add', '2001:db8::2/64', 'dev', 'guard0',
                    'valid_lft', '60', 'preferred_lft', '30', 'nodad'], check=True)
    before = capture()
    time.sleep(1.2)
    after = capture()
    (directory / 'before.json').write_text(json.dumps(before, indent=2)+'\n')
    (directory / 'after.json').write_text(json.dumps(after, indent=2)+'\n')


class HostNetworkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(['unshare', '--net', sys.executable, str(Path(__file__).resolve()),
                        '--child', '--directory', str(OUTPUT), '--parent',
                        os.readlink('/proc/self/ns/net')], check=True)
        cls.before = json.loads((OUTPUT / 'before.json').read_text())
        cls.after = json.loads((OUTPUT / 'after.json').read_text())

    def test_actual_countdown_preserves_address_expiry(self):
        self.assertNotEqual(self.before['interfaces'], self.after['interfaces'],
                            'the old raw comparison must reject this real countdown')
        report = verify(self.before, self.after)
        self.assertEqual(len(report['finite_expiry_bins_checked']), 4)
        self.assertTrue(report['interfaces_unchanged'])
        (OUTPUT / 'audit.json').write_text(json.dumps(report, indent=2)+'\n')

    def test_changed_configuration_and_lifetimes_reject(self):
        index = next(index for index, row in enumerate(self.after['interfaces'])
                     if row['ifname'] == 'guard0')
        interface = self.after['interfaces'][index]
        finite = next(index for index, row in enumerate(interface['addr_info'])
                      if row['local'] == '192.0.2.2')
        permanent = next(index for index, row in enumerate(interface['addr_info'])
                         if row['local'] == '192.0.2.3')
        controls = []
        for name in ('address', 'mtu', 'namespace', 'missing-address', 'renewed',
                     'early-expiry', 'permanent', 'clock', 'frozen-countdown'):
            changed = copy.deepcopy(self.after)
            entry = changed['interfaces'][index]
            address = entry['addr_info'][finite]
            if name == 'address':
                address['local'] = '192.0.2.4'
            elif name == 'mtu':
                entry['mtu'] += 1
            elif name == 'namespace':
                changed['namespace'] += '-different'
            elif name == 'missing-address':
                entry['addr_info'].pop(finite)
            elif name == 'renewed':
                address['valid_life_time'] += 10
            elif name == 'early-expiry':
                address['valid_life_time'] -= 10
            elif name == 'permanent':
                self.assertEqual(entry['addr_info'][permanent]['valid_life_time'], FOREVER)
                entry['addr_info'][permanent]['valid_life_time'] = 3600
            elif name == 'clock':
                changed['begin_ns'] = self.before['begin_ns'] - 1
            elif name == 'frozen-countdown':
                changed['begin_ns'] += 5 * SECOND
                changed['end_ns'] += 5 * SECOND
                address.update({key: self.before['interfaces'][index]['addr_info'][finite][key]
                                for key in ('valid_life_time', 'preferred_life_time')})
            with self.subTest(name=name):
                with self.assertRaises(ValueError) as error:
                    verify(self.before, changed)
                controls.append(dict(name=name, rejected=str(error.exception), snapshot=changed))
        (OUTPUT / 'negative-controls.json').write_text(json.dumps(controls, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/http-host-network-controls')
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--parent')
    args, remaining = parser.parse_known_args()
    if args.child:
        observe(args.directory.resolve(), args.parent)
    else:
        if os.geteuid():
            parser.error('run as root to create an isolated network namespace')
        OUTPUT = args.directory.resolve()
        OUTPUT.mkdir(parents=True, exist_ok=False)
        result = unittest.main(argv=[sys.argv[0], *remaining], exit=False)
        sys.exit(not result.result.wasSuccessful())

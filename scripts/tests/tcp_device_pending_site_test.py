#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep the device observer on its actual owned IPv4 queue site."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tcp_device.physical import pending_output_line

PREDICATE = '        if (!info || !info->live || !info->administrative || !info->carrier) {'
QUEUE = '        auto info = net_info(item.index);\n' + PREDICATE + '\n        }\n'


class PendingSiteTests(unittest.TestCase):
    def site(self, text):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'core.cpp'
            path.write_text(text)
            return pending_output_line(path)

    def test_ignore_same_condition_in_other_function(self):
        prefix = 'void route() {\n' + QUEUE + '}\n'
        body = 'void ipv4_poll() {\n' + QUEUE + '}\n'
        expected = len(prefix.splitlines()) + 3
        self.assertEqual(self.site(prefix + body), expected)

    def test_ignore_unrelated_interface_guard_inside_poll(self):
        text = ('void ipv4_poll() {\n        auto info = net_info(neighbor.index);\n' +
                PREDICATE + '\n        }\n' + QUEUE + '}\n')
        self.assertEqual(self.site(text), 6)

    def test_reject_missing_owned_site(self):
        with self.assertRaisesRegex(ValueError, 'one owned output-queue observation site'):
            self.site('void route() {\n' + QUEUE + '}\nvoid ipv4_poll() {\n}\n')

    def test_reject_ambiguous_owned_sites(self):
        with self.assertRaisesRegex(ValueError, 'one owned output-queue observation site'):
            self.site('void ipv4_poll() {\n' + QUEUE + QUEUE + '}\n')

    def test_actual_source_contains_competing_guard(self):
        path = Path(__file__).resolve().parents[2] / 'kernel/net/ipv4/core.cpp'
        lines = path.read_text().splitlines()
        self.assertGreater(sum(PREDICATE.strip()[:-2] in line for line in lines), 1)
        line = pending_output_line(path)
        self.assertGreater(line, lines.index('void ipv4_poll() {') + 1)
        self.assertEqual(lines[line - 2].strip(), 'auto info = net_info(item.index);')


if __name__ == '__main__':
    unittest.main()

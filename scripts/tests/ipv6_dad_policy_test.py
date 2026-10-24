# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep release-specific route expectations tied to the audited upstream change."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_dad_policy import retain_exhausted_prefix


class PrefixCleanupPolicy(unittest.TestCase):
    def test_audited_old_and_new_kernel_sources(self):
        for release in ('6.6.87.2-microsoft-standard-WSL2', '6.7', '6.17.0-1022-azure', '6.18.1'):
            with self.subTest(release=release):
                self.assertTrue(retain_exhausted_prefix(release))
        for release in ('6.19', '6.19.1', '7.0.0-1017-azure'):
            with self.subTest(release=release):
                self.assertFalse(retain_exhausted_prefix(release))

    def test_unaudited_or_malformed_releases_fail(self):
        for release in ('6.5.0', '7.1.0', '8.0', '', '6', '7.0;true', '6.18-'):
            with self.subTest(release=release), self.assertRaises(ValueError):
                retain_exhausted_prefix(release)


if __name__ == '__main__':
    unittest.main()

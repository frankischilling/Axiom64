# SPDX-License-Identifier: GPL-3.0-or-later
"""Regression for controls generated from a log containing several cohorts."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_source_policy_contract import FIXTURE, MARKER, verify_saved


class SourcePolicyControls(unittest.TestCase):
    def test_controls_change_the_source_cohort_in_a_mixed_log(self):
        rows = json.loads(FIXTURE.read_text())['observations']
        # This is a reader fixture, not an execution or packet-clock receipt.
        text = 'OTHER_COHORT error=0 bound=0 source=2001:db8:10::1\n'
        text += ''.join('IPV6_SOURCE_POLICY ' + ' '.join(f'{key}={value}' for key, value in row.items()) + '\n'
                        for row in rows)
        text += MARKER + '\n'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'mixed.log'
            path.write_text(text)
            proof = verify_saved(path, Path(directory) / 'controls.zip')
        self.assertEqual(proof['observations'], 114)
        self.assertEqual(proof['damaged_rejected'], 124)


if __name__ == '__main__':
    unittest.main()

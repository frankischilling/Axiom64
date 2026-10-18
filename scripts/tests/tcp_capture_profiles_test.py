# SPDX-License-Identifier: GPL-3.0-or-later
"""The public PMTU and pressure audit boundary must require every unique profile."""
from copy import deepcopy
import importlib
import itertools
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class CaptureProfileRegression(unittest.TestCase):
    def cohorts(self):
        return ([dict(linkage=value, client_namespace='net:[1]')
                 for value in ('native', 'static', 'dynamic')],
                [dict(linkage=linkage, firmware=firmware, transport=transport)
                 for linkage, firmware, transport in itertools.product(
                     ('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy'))])

    def test_complete_cohorts_reach_the_per_row_auditor(self):
        for name in ('tcp_pmtu_capture', 'tcp_pressure_capture'):
            module = importlib.import_module(name)
            for cohort in self.cohorts():
                with self.subTest(module=name, profiles=len(cohort)), tempfile.TemporaryDirectory() as temporary:
                    report = Path(temporary) / 'report.json'
                    report.write_text(json.dumps(cohort))
                    with patch.object(module, 'audit_row', return_value={'passed': True}) as verify:
                        self.assertEqual(len(module.audit(report)), len(cohort))
                        self.assertEqual(verify.call_count, len(cohort))

    def test_incomplete_or_repeated_profiles_fail_before_reading_artifacts(self):
        for name in ('tcp_pmtu_capture', 'tcp_pressure_capture'):
            module = importlib.import_module(name)
            for cohort in self.cohorts():
                duplicate = deepcopy(cohort)
                duplicate[-1] = deepcopy(duplicate[0])
                unknown = deepcopy(cohort)
                unknown[-1]['linkage'] = 'unknown'
                mixed = deepcopy(cohort)
                if 'client_namespace' in mixed[-1]:
                    del mixed[-1]['client_namespace']
                else:
                    mixed[-1]['client_namespace'] = 'net:[2]'
                for label, rows in (('missing', cohort[:-1]), ('duplicate', duplicate),
                                    ('unknown', unknown), ('mixed', mixed), ('empty', [])):
                    with self.subTest(module=name, profiles=len(cohort), damage=label), tempfile.TemporaryDirectory() as temporary:
                        report = Path(temporary) / 'report.json'
                        report.write_text(json.dumps(rows))
                        with patch.object(module, 'audit_row', return_value={'passed': True}) as verify:
                            with self.assertRaisesRegex(ValueError, 'complete unique.*capture cohort|nonempty original'):
                                module.audit(report)
                            verify.assert_not_called()


if __name__ == '__main__':
    unittest.main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Check real ownership-client argument rejection before network configuration."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class OwnershipArguments(unittest.TestCase):
    def test_invalid_arguments_fail_before_privileged_operations(self):
        invalid=[[],['--group'],['--group','unknown'],['--retain-exhausted-routes'],
                 ['--group','global','--unknown'],['--group','lifecycle','--group','global'],
                 ['--group','global','--retain-exhausted-routes','--duplicate'],
                 ['--unknown','global']]
        with tempfile.TemporaryDirectory(prefix='axiom64-owner-arguments-') as temporary:
            program=Path(temporary)/'client'
            result=subprocess.run(['gcc','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
                'userspace/tests/net/ipv6_address_ownership.c','-o',str(program)],cwd=ROOT,
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode,0,result.stdout.decode(errors='replace'))
            for arguments in invalid:
                with self.subTest(arguments=arguments):
                    result=subprocess.run([str(program),*arguments],stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=2)
                    self.assertEqual(result.returncode,1)
                    self.assertIn(b'IPV6_OWNER_FAIL known ownership group and pinned prefix policy',result.stdout)
                    self.assertNotIn(b'configuration file',result.stdout)


if __name__=='__main__':unittest.main()
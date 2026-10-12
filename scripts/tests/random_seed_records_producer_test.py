#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual init formatter at every captured input-echo boundary."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from random_installed_records import seed_records

PREFIX = "/ # printf '%s%s\\n' INSTALLED_RANDOM_ CONSOLE"


class Producer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='init-seed-record-')
        directory = Path(cls.temporary.name)
        source = directory/'producer.c'
        source.write_text('''#include <stdio.h>
#include "seed_records.h"
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    fputs(argv[1], stdout);
    init_seed_spawned_record(13, 13840);
    fputs(argv[1], stdout);
    init_seed_reaped_record(3, 0, 2270);
    fputs(argv[1], stdout);
    init_seed_reaped_record(13, 256, 13840);
    return 0;
}
''')
        cls.executable = directory/('producer.exe' if os.name == 'nt' else 'producer')
        compiler = shutil.which('gcc')
        if not compiler:
            raise RuntimeError('the actual C formatter test requires GCC')
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                        '-I', str(ROOT/'userspace/init'), str(source), '-o', str(cls.executable)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_every_input_echo_boundary(self):
        for boundary in range(len(PREFIX)+1):
            with self.subTest(boundary=boundary):
                result = subprocess.run([str(self.executable), PREFIX[:boundary]], capture_output=True, check=True)
                text = result.stdout.decode().replace('\r\n', '\n')
                self.assertEqual(seed_records(text, 'SPAWN'), [('13', '13840')])
                self.assertEqual(seed_records(text, 'REAP'), [('3', '0', '2270'), ('13', '256', '13840')])
                for marker in ('INIT_RANDOM_SEED_SPAWN', 'INIT_RANDOM_SEED_REAP'):
                    self.assertTrue(all(at == 0 or text[at-1] == '\n' for at in
                        range(len(text)) if text.startswith(marker, at)))

    def test_partial_timestamps_and_sender_text_stay_rejected(self):
        record = 'INIT_RANDOM_SEED_REAP pid=3 status=0 monotonic_ms=2270\n'
        for boundary in range(len(record)):
            self.assertEqual(seed_records(record[:boundary], 'REAP'), [])
        actual = "/ # printf '%s%s\\n' I"+record+'NSTALLED_RANDOM_ CONSOLE\n'
        self.assertEqual(seed_records(actual, 'REAP'), [])
        sender = "/ # printf '"+record.rstrip('\n')+"\\n'\n"
        self.assertEqual(seed_records(sender, 'REAP'), [])


if __name__ == '__main__':
    unittest.main()

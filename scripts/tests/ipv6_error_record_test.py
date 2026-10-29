#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay the actual interrupted ICMPv6 formatter at console write boundaries."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ipv6_error_metadata_capture import samples


class MetadataRecords(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / 'scripts/tests/fixtures/ipv6-error-metadata-interrupted.json').read_text())
        cls.temporary = tempfile.TemporaryDirectory(prefix='axiom64-error-record-')
        directory = Path(cls.temporary.name)
        line = cls.fixture['formatter_record']
        row = dict(value.split('=', 1) for value in line.split()[1:])
        arrays = []
        for key in ('before_header', 'header', 'name', 'name_prefix', 'control', 'payload', 'drain'):
            data = bytes.fromhex(row[key])
            arrays.append('unsigned char ' + key + '[] = {' + ','.join(str(value) for value in data or b'\0') + '};')
        fields = dict(lane='lane', sequence='case', kind='kind', scoped='scope', variant='variant',
                      mask='mask', capacity='capacity', input_flags='input_flags', result='result',
                      queued='queued', normal='normal', error='errno', queue_error='queue_errno',
                      normal_error='normal_errno', control_visible='control_visible', name_visible='name_visible')
        values = ',\n'.join('.' + key + ' = ' + row[value] for key, value in fields.items())
        source = r'''#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
static unsigned writes;
static int partial;
ssize_t observed_write(int fd, const void* data, size_t length) {
    writes++;
    if (partial) return (ssize_t)length - 1;
    ssize_t result = syscall(SYS_write, fd, data, length);
    const char diagnostic[] = "RANDOM_RESEEDED source=rdseed bits=256\n";
    if (syscall(SYS_write, fd, diagnostic, sizeof(diagnostic) - 1) != sizeof(diagnostic) - 1)
        return -1;
    return result;
}
int observed_printf(const char* format, ...) {
    char data[4096];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(data, sizeof(data), format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof(data)) return -1;
    return (int)observed_write(STDOUT_FILENO, data, (size_t)length);
}
#define write observed_write
#define printf observed_printf
#include "ipv6_error_record.h"
#undef printf
#undef write
int main(int argc, char** argv) {
    (void)argv;
    partial = argc == 2 && !strcmp(argv[1], "partial");
    if (argc == 2 && !strcmp(argv[1], "buffered"))
        fputs("PREVIOUS_RECORD complete\n", stdout);
''' + '\n'.join(arrays) + r'''
    struct msghdr before, after;
    memcpy(&before, before_header, sizeof(before));
    memcpy(&after, header, sizeof(after));
    struct metadata_record record = {
        .label = "IPV6_ERROR_EXTENSIONS",
        .before = &before, .after = &after, .name = name, .name_prefix = name_prefix,
        .control = control, .payload = payload, .drain = drain,
''' + values + r'''};
    int result = emit_metadata_record(&record);
    fprintf(stderr, "writes=%u result=%d\n", writes, result);
    return result ? 1 : 0;
}
'''
        (directory / 'producer.c').write_text(source)
        cls.executable = directory / 'producer'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I',
                        str(ROOT / 'userspace/tests/net'), str(directory / 'producer.c'),
                        '-o', str(cls.executable)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_actual_failed_record_remains_rejected(self):
        raw = bytes.fromhex(self.fixture['original_interrupted_record_hex'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.fixture['original_interrupted_record_sha256'])
        with self.assertRaisesRegex(ValueError, 'exact metadata result inventory'):
            samples(raw.decode(), 1, outer=True)

    def test_actual_formatter_keeps_every_byte_in_one_write(self):
        result = subprocess.run([str(self.executable)], capture_output=True, check=True)
        self.assertEqual(result.stderr, b'writes=1 result=0\n')
        self.assertEqual(result.stdout, (self.fixture['formatter_record'] + self.fixture['diagnostic'] + '\n').encode())

    def test_partial_record_write_fails(self):
        result = subprocess.run([str(self.executable), 'partial'], capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'writes=1 result=-1\n')

    def test_pending_stdio_records_precede_direct_write(self):
        result = subprocess.run([str(self.executable), 'buffered'], capture_output=True, check=True)
        expected = ('PREVIOUS_RECORD complete\n' + self.fixture['formatter_record'] +
                    self.fixture['diagnostic'] + '\n').encode()
        self.assertEqual(result.stdout, expected)
        self.assertEqual(result.stderr, b'writes=1 result=0\n')


if __name__ == '__main__':
    unittest.main()

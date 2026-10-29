# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual reconnect client's wait at fractional millisecond starts."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ReconnectElapsedWait(unittest.TestCase):
    def test_full_interval_at_original_and_fractional_clock_boundaries(self):
        # Only this host test supplies clocks. Runtime clients use CLOCK_MONOTONIC.
        source = r'''
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
static uint64_t observed_ns;
static unsigned sleeps;
static int observed_clock(clockid_t clock, struct timespec *value) {
    if (clock != CLOCK_MONOTONIC) return -1;
    value->tv_sec = observed_ns / 1000000000;
    value->tv_nsec = observed_ns % 1000000000;
    return 0;
}
static int observed_sleep(useconds_t microseconds) {
    if (!microseconds || microseconds > 100000) return -1;
    observed_ns += (uint64_t)microseconds * 1000;
    sleeps++;
    return 0;
}
#define clock_gettime observed_clock
#define usleep observed_sleep
#define main reconnect_fixture_main
#include CLIENT_SOURCE
#undef main
#undef clock_gettime
#undef usleep
static int check_wait(uint64_t began, uint64_t now, int exact_boundary) {
    observed_ns = now;
    sleeps = 0;
    wait_queued_lifetime(began);
    if (observed_ns - began < 11000000000ULL ||
        observed_ns - began >= 11000001000ULL || (exact_boundary && sleeps)) {
        fprintf(stderr, "full real interval missing: began=%llu elapsed=%llu sleeps=%u\n",
                (unsigned long long)began, (unsigned long long)(observed_ns-began), sleeps);
        return 1;
    }
    return 0;
}
int main(void) {
    /* The original failing capture's ARM and recovery observations. */
    if (check_wait(1555909685802ULL, 1566909608000ULL, 0)) return 1;
    for (unsigned fraction = 1; fraction < 1000000; fraction += 997) {
        uint64_t began = 100000000000ULL + fraction;
        if (check_wait(began, began + 11000000000ULL - fraction, 0)) return 1;
        if (check_wait(began, began + 11000000000ULL, 1)) return 1;
    }
    return check_wait(100000000000ULL, 100000000000ULL, 0);
}
'''.replace('CLIENT_SOURCE', json.dumps((ROOT / 'userspace/tests/net/tcp_reconnect.c').as_posix()))
        with tempfile.TemporaryDirectory(prefix='axiom64-reconnect-clock-') as temporary:
            directory = Path(temporary)
            path = directory / 'wait.c'
            path.write_text(source)
            executable = directory / 'wait'
            compiled = subprocess.run(['cc', '-std=c11', '-D_DEFAULT_SOURCE', '-Wall', '-Wextra',
                '-Werror', str(path), '-o', str(executable)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            checked = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == '__main__':
    unittest.main()

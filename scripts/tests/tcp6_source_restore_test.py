#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check the real source-restoration helper before releasing incoming packets."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/tcp6-source-restore-control')
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'userspace/tests/net/tcp6/source_expiry.c'
    # Include the actual client so this exercises its mutation/route boundary.
    harness = '#define main full_expiry_workload\n#include "' + source.as_posix() + '"\n'
    harness += r'''
#undef main
#include <net/if.h>
int main(void) {
    indices[0] = if_nametoindex("eth0");
    check(indices[0] != 0, "actual restoration interface");
    unsigned missing = 0;
    for (unsigned n = 0; n < 3000; n++) {
        mutation(0, 2, 1);
        missing += !local_route_ready(0, 2);
        mutation(0, 2, 0);
        check(!local_route_ready(0, 2), "removed local input route stays absent");
    }
    printf("RESTORE_HANDOFF attempts=3000 missing=%u\n", missing);
    return missing != 0;
}
'''
    (directory / 'test.c').write_text(harness)
    subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(ROOT / 'userspace/tests/net'), str(directory / 'test.c'),
                    '-o', str(directory / 'test')], check=True)
    # All link/address mutations stay inside this disposable network namespace.
    result = subprocess.run(['unshare', '--net', 'sh', '-ec',
        'ip link add eth0 type dummy; ip link set eth0 up; exec "$1"',
        'sh', str(directory / 'test')], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    (directory / 'output.log').write_text(result.stdout)
    print(result.stdout, end='')
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())

# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the sanitized option engine with retained Linux observations."""
import os
import subprocess

from fetch import ROOT
from ipv4_options.fixtures import receive_table, socket_table
from ipv4_options.policy_test import verify_retained_policies


def main():
    verify_retained_policies()
    program = ROOT / 'build/ipv4-options-host'
    environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    for arguments, table, marker in [([], socket_table(), 'IPV4_OPTIONS_HOST_PASS native_observations=14220'),
                                     (['receive'], receive_table(), 'IPV4_OPTIONS_RECEIVE_HOST_PASS native_observations=214')]:
        result = subprocess.run([str(program), *arguments], cwd=ROOT, input=table,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env=environment, timeout=60)
        text = result.stdout.decode()
        print(text, end='')
        if result.returncode or text.count(marker) != 1:
            raise RuntimeError('IPv4 option model did not complete its native comparison')


if __name__ == '__main__':
    main()

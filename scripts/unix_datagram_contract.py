# SPDX-License-Identifier: GPL-3.0-or-later
"""The public Unix datagram clients and their complete guest result contract."""
import re

CLIENTS = {'unix_messages': 11, 'unix_names': 6, 'unix_routing': 5,
           'unix_routing_wait': 7, 'unix_credentials': 5, 'unix_rights': 7}


def boot_body():
    lines = ['/bin/busybox chmod 1777 /tmp']
    for name in CLIENTS:
        program = '/bin/' + name.replace('_', '-')
        lines += [program, program + ' --ordinary']
    return '\n'.join(lines)


def check_log(text, firmware, returncode):
    lines = text.splitlines()
    if returncode != 1 or any(word in text for word in ('_FAIL', 'PANIC:', 'FAULT pid=')):
        raise ValueError('Unix datagram guest did not exit successfully')
    for marker in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0', 'Firmware: ' + firmware.upper()):
        if lines.count(marker) != 1:
            raise ValueError('missing or repeated guest marker: ' + marker)
    for name, groups in CLIENTS.items():
        prefix = name.upper()
        if lines.count(f'{prefix}_PASS groups={groups}') != 2:
            raise ValueError('missing or repeated complete client result: ' + name)
        identities = [line for line in lines if line.startswith(prefix + '_IDENTITY ')]
        expected = [f'uid={uid} euid={uid} gid={uid} egid={uid} groups=0' for uid in (0, 65534)]
        if len(identities) != 2 or any(value not in line for value, line in zip(expected, identities)):
            raise ValueError('client did not run under both controlled identities: ' + name)
    invocations = re.findall(r'^exec pid=\d+ /bin/(unix-[a-z-]+) \((static ELF|dynamic musl)\)$', text, re.M)
    invocations = [(name, kind.split()[0]) for name, kind in invocations]
    expected = [name.replace('_', '-') for name in CLIENTS for _ in range(2)]
    if [name for name, _ in invocations] != expected:
        raise ValueError('guest did not execute each complete client twice in order')
    for endpoints in (240, 128):
        prefix = f'UNIX_RIGHTS_CHAIN_PASS endpoints={endpoints} limit=128 '
        if sum(line.startswith(prefix) for line in lines) != 1:
            raise ValueError('missing privileged or limit-bounded ordinary chain release')
    return invocations

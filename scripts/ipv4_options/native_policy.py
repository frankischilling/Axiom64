# SPDX-License-Identifier: GPL-3.0-or-later
"""Identify one of two retained native source-route policies before comparison."""
import json
import os
import socket

from ipv4_options.fixtures import LEGACY_SOCKET, SOCKET


def verify_policy(proof):
    """Validate fixed native probes; guest expectations never come from this probe."""
    if (set(proof) != {'schema', 'kernel', 'uid', 'gid', 'effective_capabilities', 'rows', 'fixture'} or
            type(proof['schema']) is not int or proof['schema'] != 1 or
            not isinstance(proof['kernel'], str) or not proof['kernel'] or
            proof['uid'] != 65534 or proof['gid'] != 65534 or proof['effective_capabilities'] != '0000000000000000'):
        raise ValueError('complete ordinary native source-route policy identity')
    rows = proof['rows']
    if not isinstance(rows, list) or len(rows) != 2:
        raise ValueError('both fixed ordinary native source-route probes')
    policies = []
    for kind, row in zip((131, 137), rows):
        value = bytes((kind, 7, 4, 0, 0, 0, 0)).hex()
        if set(row) != {'input', 'result', 'output'} or row['input'] != value or type(row['result']) is not int:
            raise ValueError('unchanged native source-route probe bytes')
        if row['result'] == -1 and row['output'] == '01010101':
            policies.append(SOCKET.name)
        elif row['result'] == 0 and row['output'] == value + '00':
            policies.append(LEGACY_SOCKET.name)
        else:
            raise ValueError('native source-route probe differs from both retained policies')
    if policies[0] != policies[1] or proof['fixture'] != policies[0]:
        raise ValueError('one consistent retained native source-route policy')
    return SOCKET if policies[0] == SOCKET.name else LEGACY_SOCKET


def capture_policy():
    if os.geteuid() != 0:
        raise ValueError('native policy probe requires root before dropping credentials')
    reader, writer = os.pipe()
    # The inherited descriptor establishes caller credentials, independently of
    # descriptor creation credentials, just like the exhaustive C client.
    descriptor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    child = os.fork()
    if not child:
        os.close(reader)
        try:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            with open('/proc/self/status') as stream:
                capabilities = next(line.split()[1] for line in stream if line.startswith('CapEff:'))
            rows = []
            for kind in (131, 137):
                descriptor.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, b'\1' * 4)
                value = bytes((kind, 7, 4, 0, 0, 0, 0))
                try:
                    descriptor.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, value)
                    result = 0
                except OSError as error:
                    result = -error.errno
                rows.append(dict(input=value.hex(), result=result,
                                 output=descriptor.getsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, 40).hex()))
            proof = dict(schema=1, kernel=os.uname().release, uid=os.geteuid(), gid=os.getegid(),
                         effective_capabilities=capabilities, rows=rows,
                         fixture=SOCKET.name if rows[0]['result'] == -1 else LEGACY_SOCKET.name)
            verify_policy(proof)
            with os.fdopen(writer, 'w') as stream:
                json.dump(proof, stream)
        except BaseException:
            os._exit(1)
        os._exit(0)
    os.close(writer)
    descriptor.close()
    with os.fdopen(reader) as stream:
        data = stream.read()
    waited, status = os.waitpid(child, 0)
    if waited != child or not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        raise ValueError('ordinary native source-route policy probe failed')
    proof = json.loads(data)
    return proof, verify_policy(proof)

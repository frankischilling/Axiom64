#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build and verify the actual Linux counter contract used by download clients."""
from pathlib import Path
import json
import re
import subprocess

from build_musl import compiler_args, ensure as musl
from build_openssl import elf, native_inputs
from fetch import ROOT
from random_administration_test import fingerprint

GROUPS = ('creation', 'counters', 'faults-vectors', 'readiness', 'retained-io',
          'interruption', 'inheritance')


def build(directory, provider, linkage):
    source = ROOT / 'userspace/tests/ipc/eventfd.c'
    program = directory / 'eventfd-test'
    compiler = ['gcc'] if provider == 'native' else compiler_args(provider)
    command = [*compiler, '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               *(['-static'] if linkage == 'static' else []), str(source), '-o', str(program)]
    with (directory / 'eventfd-build.log').open('wb') as log:
        subprocess.run(command, cwd=ROOT, check=True, stdout=log, stderr=subprocess.STDOUT)
    record = dict(command=command, source=fingerprint(source), binary=fingerprint(program),
        elf=elf(program), provider=provider, linkage=linkage,
        libc_manifest=fingerprint(musl(provider) / 'manifest.json') if provider != 'native' else None,
        native_inputs=native_inputs() if provider == 'native' else {})
    if linkage == 'static':
        assert 'INTERP' not in record['elf']['program_headers']
        assert '(NEEDED)' not in record['elf']['dynamic']
    elif provider != 'native':
        assert '/lib/ld-musl-x86_64.so.1' in record['elf']['program_headers']
        assert 'libc.so.6' not in record['elf']['dynamic']
    (directory / 'eventfd-build.json').write_text(json.dumps(record, indent=2)+'\n')
    return program, record


def verify(text, *, strict):
    groups = re.findall(r'^EVENTFD_GROUP_PASS ([a-z-]+)\r?$', text, re.M)
    if tuple(groups) != GROUPS or len(re.findall(r'^EVENTFD_PASS groups=7\r?$', text, re.M)) != 1:
        raise RuntimeError('actual eventfd contract groups did not complete')
    begin = re.findall(r'^EVENTFD_BEGIN uid=([0-9]+) strict=([01])\r?$', text, re.M)
    if len(begin) != 1 or int(begin[0][0]) == 0 or bool(int(begin[0][1])) != strict:
        raise RuntimeError('eventfd contract lacks its actual ordinary identity and size policy')
    size = re.findall(r'^EVENTFD_WRITE_SIZE strict=([01]) result=(-?[0-9]+) errno=([0-9]+)\r?$', text, re.M)
    if len(size) != 1 or bool(int(size[0][0])) != strict:
        raise RuntimeError('eventfd write-size observation is missing')
    result, error = map(int, size[0][1:])
    if (result, error) != (-1, 22) and (strict or (result, error) != (8, 0)):
        raise RuntimeError('unexpected actual Linux eventfd write-size contract')
    return dict(passed=True, groups=len(groups), uid=int(begin[0][0]), strict=strict,
                oversized_write=dict(result=result, error=error))

#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compile an ABI fixture with the pinned target UAPI and retain its inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

from build_musl import compiler_args
from build_openssl import uapi_headers


def sources(command, root=Path('.')):
    if command[-2:-1] != ['-o']:
        raise ValueError('client compiler command must end with its output path')
    dependencies = subprocess.check_output(command[:-2] + ['-MM'], text=True, cwd=root).replace('\\\n', '')
    paths = {name for row in dependencies.splitlines()
             for name in shlex.split(row.partition(':')[2])}
    if not paths:
        raise ValueError('compiler did not report client source dependencies')
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(paths)}


def audit_compile(binary, root=Path('.')):
    saved = json.loads(binary.with_suffix('.inputs.json').read_text())
    if saved['product']['sha256'] != hashlib.sha256(binary.read_bytes()).hexdigest():
        raise ValueError('client compile manifest does not match executable')
    recorded = saved.get('sources', {})
    command_sources = {name for name in saved['command'] if name.endswith(('.c', '.cpp'))}
    if not command_sources or command_sources != {name for name in recorded if name.endswith(('.c', '.cpp'))}:
        raise ValueError('client compile manifest does not bind all command sources')
    if sources(saved['command'], root) != recorded:
        raise ValueError('client source changed after compilation')
    return saved


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', help='Native compiler command; defaults to the pinned musl compiler')
    parser.add_argument('flags', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    headers, provenance = uapi_headers()
    flags = args.flags[1:] if args.flags[:1] == ['--'] else args.flags
    compiler = shlex.split(args.compiler) if args.compiler else compiler_args('build')
    if not compiler:
        parser.error('compiler command must not be empty')
    command = compiler + ['-isystem', str(headers), *flags, '-o', str(args.output)]
    inputs = sources(command)
    subprocess.run(command, check=True)
    if sources(command) != inputs:
        raise ValueError('client sources changed during compilation')
    saved = dict(command=command, compiler=shlex.join(compiler),
                 uapi=provenance, sources=inputs, product=dict(bytes=args.output.stat().st_size,
                    sha256=hashlib.sha256(args.output.read_bytes()).hexdigest()))
    args.output.with_suffix('.inputs.json').write_text(json.dumps(saved, indent=2)+'\n')


if __name__ == '__main__':
    main()

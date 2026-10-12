#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compile a musl ABI fixture with the pinned target UAPI and retain its inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

from build_musl import compiler_args
from build_openssl import uapi_headers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('flags', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    headers, provenance = uapi_headers()
    flags = args.flags[1:] if args.flags[:1] == ['--'] else args.flags
    command = compiler_args('build') + ['-isystem', str(headers), *flags, '-o', str(args.output)]
    subprocess.run(command, check=True)
    saved = dict(command=command, compiler=shlex.join(compiler_args('build')),
                 uapi=provenance, product=dict(bytes=args.output.stat().st_size,
                    sha256=hashlib.sha256(args.output.read_bytes()).hexdigest()))
    args.output.with_suffix('.inputs.json').write_text(json.dumps(saved, indent=2)+'\n')


if __name__ == '__main__':
    main()

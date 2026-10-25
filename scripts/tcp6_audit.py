#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reopen a retained IPv6 TCP runtime matrix and negative controls."""
import argparse
from pathlib import Path
from tcp6.evidence import audit

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output-directory', type=Path)
    args = parser.parse_args()
    audit(args.directory.resolve(), args.output_directory.resolve() if args.output_directory else None)

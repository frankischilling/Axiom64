#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compile against the checked local musl sysroot and the guest interpreter path."""
import os
import sys
from build_musl import compiler_args

command = compiler_args()
os.execvp(command[0], command + sys.argv[1:])

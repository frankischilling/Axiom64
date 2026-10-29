# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain the shared configuration client's source and execution products."""
import json
import shutil

from build_musl import loader
from compile_uapi_client import audit_compile
from fetch import ROOT
from tcp6.inputs import digest, freeze, source_names

COMMON = ['ADDRESS_MESSAGES', 'ROUTE_LIFETIME', 'ROUTE_VARIANTS', 'REPLACEMENT_RECOVERY',
          'MANUAL_PRESERVATION', 'CORRUPT_JOURNAL', 'JOURNAL_FAILURE', 'INTENT_RECOVERY',
          'PROCESS_RECOVERY', 'TESTS']
PROGRAMS = {'native': 'configuration-native', 'static': 'configuration-tests',
            'dynamic': 'configuration-dynamic'}


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def retain(directory, profile):
    directory.mkdir()
    original = ROOT / 'build' / PROGRAMS[profile]
    compiled = audit_compile(original, ROOT)
    if ('-static' in compiled['command']) != (profile == 'static'):
        raise ValueError('configuration executable has the wrong linkage')
    shutil.copy2(original, directory / 'program.elf')
    shutil.copy2(original.with_suffix('.inputs.json'), directory / 'program.inputs.json')
    products = {name: digest(directory / name) for name in ('program.elf', 'program.inputs.json')}
    if profile == 'dynamic':
        shutil.copy2(loader('build'), directory / 'loader.elf')
        products['loader.elf'] = digest(directory / 'loader.elf')
    return dict(profile=profile, program=PROGRAMS[profile], products=products,
                compile_sources=compiled['sources'])


def unchanged(directory):
    records = json.loads((directory / 'source-inputs.json').read_text())
    names, _ = source_names()
    return set(names) == set(records) and all(digest(ROOT / name) == value for name, value in records.items())


def missing(text, native):
    names = COMMON + (['PRESERVATION_BOUND', 'TOS_OWNERSHIP'] if native else ['ADDRESS_PRESSURE', 'ROLLBACK'])
    absent = ['CONFIGURATION_' + name + '_PASS' for name in names
              if 'CONFIGURATION_' + name + '_PASS' not in text]
    if not native:
        absent += [name for name in ('AXIOM64_TESTS_PASS', 'AXIOM64_EXIT status=0') if name not in text]
    return absent

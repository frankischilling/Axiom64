# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual manual-source observations against an executed Linux reference."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import zipfile
from fetch import ROOT

FIXTURE = ROOT / 'scripts/tests/fixtures/ipv6-source-policy-linux7.json'
PREFIX = 'IPV6_SOURCE_POLICY'
MARKER = 'IPV6_SOURCE_POLICY_PASS adapters=2 observations=114'
LINK_SOURCES = frozenset(ipaddress.IPv6Address(value).packed for value in ('fe80::1', 'fe80::10'))


def records(text):
    output = []
    complete = 0
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        if line == MARKER:
            complete += 1
            continue
        if not line.startswith(PREFIX + ' '):
            raise ValueError('unknown or failed source-policy observation')
        pairs = [part.split('=', 1) for part in line[len(PREFIX) + 1:].split()]
        if any(len(pair) != 2 for pair in pairs):
            raise ValueError('incomplete source-policy fields')
        row = dict(pairs)
        if len(row) != len(pairs) or set(row) != {'lane', 'case', 'bound', 'error', 'source'}:
            raise ValueError('exact source-policy field inventory')
        row = {**row, **{name: int(row[name]) for name in ('lane', 'bound', 'error')},
               'source': str(ipaddress.IPv6Address(row['source']))}
        output.append(row)
    if complete != 1:
        raise ValueError('one complete source-policy execution')
    return output


def verify_log(text):
    expected = json.loads(FIXTURE.read_text())
    reference = expected['reference']
    source = ROOT / 'userspace/tests/net/ipv6_source_policy.c'
    if (expected['schema'] != 1 or reference['kernel'] != '7.0.0-1017-azure' or
            reference['source_sha256'] != hashlib.sha256(source.read_bytes()).hexdigest() or
            not reference['actual_program_completed'] or not reference['actual_cpio_reopened'] or
            len(expected['observations']) != 114):
        raise ValueError('complete executed source-bound Linux source-policy reference')
    observed = records(text)
    if observed != expected['observations']:
        raise ValueError('complete ordered source-policy outcomes match executed Linux')
    return dict(passed=True, observations=len(observed), adapters=2,
                reference=reference, packet_acceptance=False)


def verify_saved(path, archive):
    path, archive = Path(path), Path(archive)
    raw = path.read_bytes()
    text = raw.decode()
    result = verify_log(text)
    lines = text.splitlines(keepends=True)
    selected = [n for n, line in enumerate(lines) if line.startswith(PREFIX + ' ')]
    controls = {}
    for n, at in enumerate(selected):
        controls[f'missing-{n:03}.log'] = ''.join(lines[:at] + lines[at + 1:])
    first = selected[0]

    def change_first(old, new):
        if old not in lines[first]:
            raise ValueError('source-policy control input exists in the selected cohort')
        changed = list(lines)
        changed[first] = changed[first].replace(old, new, 1)
        return ''.join(changed)

    controls['duplicate.log'] = ''.join(lines[:first] + [lines[first]] + lines[first:])
    controls['duplicate-completion.log'] = text + MARKER + '\n'
    controls['missing-completion.log'] = text.replace(MARKER, '')
    controls['changed-source.log'] = change_first('source=2001:db8:10::1', 'source=2001:db8:10::9')
    controls['changed-error.log'] = change_first('error=0', 'error=99')
    controls['failed-execution.log'] = text + PREFIX + '_FAIL injected\n'
    controls['extra-field.log'] = change_first('bound=0', 'bound=0 extra=1')
    controls['duplicate-field.log'] = change_first('bound=0', 'bound=0 bound=0')
    controls['invalid-address.log'] = change_first('source=2001:db8:10::1', 'source=invalid')
    controls['unknown-case.log'] = change_first('case=outgoing-before-prefix', 'case=unknown')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as saved:
        for name, changed in controls.items():
            if changed == text:
                raise ValueError('source-policy control must change actual evidence')
            saved.writestr(name, changed)
    rejected = []
    with zipfile.ZipFile(archive) as saved:
        if set(saved.namelist()) != set(controls):
            raise ValueError('complete serialized source-policy controls')
        for name in saved.namelist():
            changed = saved.read(name).decode()
            if changed != controls[name]:
                raise ValueError('serialized source-policy control changed')
            try:
                verify_log(changed)
            except ValueError:
                rejected.append(name)
            else:
                raise ValueError('damaged source-policy evidence accepted: ' + name)
    if path.read_bytes() != raw:
        raise ValueError('original source-policy evidence changed')
    return {**result, 'damaged_rejected': len(rejected),
            'original_sha256': hashlib.sha256(raw).hexdigest(),
            'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    parser.add_argument('--archive', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_saved(args.log, args.archive), indent=2))


if __name__ == '__main__':
    main()

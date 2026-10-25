# SPDX-License-Identifier: GPL-3.0-or-later
"""Damage and freshly reopen non-IPv4 receipts from all actual TCP profiles."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from tcp_capture_profiles import require_complete_profiles
from tcp_icmp_capture import audit_row as audit_icmp, contract, require
from tcp_pmtu_capture import audit_row as audit_pmtu
from tcp_pressure_capture import audit_row as audit_pressure


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reports', nargs='*', type=Path)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/tcp-link-receipts-damaged')
    args = parser.parse_args()
    reports = args.reports or [ROOT / f'build/tcp-{name}{suffix}-results.json'
                              for name in ('icmp', 'pmtu', 'pressure') for suffix in ('-native', '')]
    destination = args.directory.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    observations, positives = [], []
    for report in reports:
        root = report.parent
        rows = json.loads(report.read_text())
        require_complete_profiles(rows)
        for ordinal, row in enumerate(rows):
            family = row['wire']
            require(family in ('icmp', 'pmtu', 'pressure'), 'known actual TCP receipt family')
            auditor = {'icmp': lambda folder, value: audit_icmp(folder, value, contract()),
                       'pmtu': audit_pmtu, 'pressure': audit_pressure}[family]
            auditor(root, row)
            prefix = family.upper()
            text = (root / row['log']).read_text()
            files = [row['log'], row['peer'], row['inputs'], *row['captures'],
                     *(value['monotonic_receipts'] for value in row.get('capture_statistics', []))]
            fingerprints = {name: digest(root / name) for name in files}
            profile = report.stem + '-' + str(ordinal)
            positives.append(dict(profile=profile, files=fingerprints))
            for lane in range(2):
                stat = re.search(rf'^{prefix}_CAPTURE_PASS lane={lane} index=\d+ packets=(\d+) '
                                 r'dropped=0 ipv4=\d+\r?$', text, re.M)
                require(stat is not None, 'actual complete TCP driver count')
                changed = text[:stat.start(1)] + str(int(stat[1]) + 1) + text[stat.end(1):]
                mutations = [('unexplained-packet', changed,
                              'exact IPv4 and non-IPv4 driver packet accounting')]
                match = re.search(rf'^{prefix}_LINK_FRAME lane={lane} index=\d+ length=\d+ '
                                  r'kind=\d+ ether_type=[0-9a-f]{4} hash=[0-9a-f]{16} '
                                  r'monotonic_ms=\d+\r?\n', text, re.M)
                if match:
                    line = match[0]
                    replacements = [
                        ('missing-receipt', '', 'exact IPv4 and non-IPv4 driver packet accounting'),
                        ('duplicate-receipt', line * 2, 'exact IPv4 and non-IPv4 driver packet accounting'),
                        ('wrong-interface', re.sub(r'index=(\d+)', lambda value: 'index=' + str(int(value[1]) + 100), line),
                         'non-IPv4 driver interface identity'),
                        ('wrong-length', re.sub(r'length=(\d+)', lambda value: 'length=' + str(int(value[1]) + 1), line),
                         'every non-IPv4 driver receipt owns an original Ethernet frame'),
                        ('wrong-direction', re.sub(r'kind=(\d+)', lambda value: 'kind=' + str((int(value[1]) + 1) % 5), line),
                         'every non-IPv4 driver receipt owns an original Ethernet frame'),
                        ('wrong-hash', re.sub(r'hash=([0-9a-f]{16})', lambda value: 'hash=' +
                                             ('1' if value[1][0] != '1' else '2') + value[1][1:], line),
                         'every non-IPv4 driver receipt owns an original Ethernet frame'),
                        ('wrong-ether-type', re.sub(r'ether_type=[0-9a-f]{4}', 'ether_type=88b4', line),
                         'every non-IPv4 driver receipt owns an original Ethernet frame'),
                        ('invalid-direction', re.sub(r'kind=\d+', 'kind=5', line),
                         'complete non-IPv4 driver receipts'),
                        ('IPv4-as-link', re.sub(r'ether_type=[0-9a-f]{4}', 'ether_type=0800', line),
                         'complete non-IPv4 driver receipts'),
                        ('malformed-receipt', line.replace('length=', 'bytes='),
                         'complete non-IPv4 driver receipts')]
                    mutations += [(label, text[:match.start()] + replacement + text[match.end():], expected)
                                  for label, replacement, expected in replacements]
                for label, changed, expected in mutations:
                    require(changed != text, 'an original TCP observation was damaged')
                    archive = destination / f'{profile}-lane{lane}-{label}.zip'
                    metadata = dict(profile=profile, lane=lane, control=label, expected=expected,
                                    original_files=fingerprints, row=row,
                                    changed_log_sha256=hashlib.sha256(changed.encode()).hexdigest())
                    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as output:
                        output.writestr(row['log'], changed)
                        output.writestr('mutation.json', json.dumps(metadata, indent=2) + '\n')
                    with tempfile.TemporaryDirectory(prefix='tcp-link-reopen-') as temporary:
                        scratch = Path(temporary)
                        for name in files:
                            shutil.copyfile(root / name, scratch / name)
                        with zipfile.ZipFile(archive) as source:
                            source.extractall(scratch)
                        reopened = json.loads((scratch / 'mutation.json').read_text())
                        require(reopened == metadata and digest(scratch / row['log']) ==
                                reopened['changed_log_sha256'], 'serialized TCP link mutation reopened exactly')
                        require(all(digest(scratch / name) == value for name, value in fingerprints.items()
                                    if name != row['log']), 'unmodified TCP evidence stays byte-identical')
                        try:
                            auditor(scratch, deepcopy(reopened['row']))
                        except ValueError as error:
                            reason = str(error)
                            require(expected in reason, f'{label}: wrong TCP link rejection: {reason}')
                        else:
                            raise ValueError(f'{label}: damaged TCP link evidence accepted')
                    observations.append(dict(profile=profile, lane=lane, control=label, reason=reason,
                                             archive=archive.name, sha256=digest(archive)))
            require(all(digest(root / name) == value for name, value in fingerprints.items()),
                    'all original TCP evidence preserved after mutations')
    value = dict(passed=True, profiles=len(positives), negative_cases=len(observations),
                 positives=positives, cases=observations)
    (destination / 'results.json').write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({key: value[key] for key in ('passed', 'profiles', 'negative_cases')}))


if __name__ == '__main__':
    main()

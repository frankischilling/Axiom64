# SPDX-License-Identifier: GPL-3.0-or-later
"""Serialize and reopen damaged syscall records against complete real control logs."""
import argparse
import copy
import json
from pathlib import Path

from ipv4_source_route.controls import decode, observations, require
from tcp6.inputs import digest, write


def verify_controls(directory, output):
    require(not output.exists(), 'new retained reader-control directory')
    output.mkdir(parents=True)
    count = 0
    for native, log in ((True, directory / 'native-static/client.log'), (False, directory / 'static/bios.log')):
        original = digest(log)
        text = log.read_text()
        observations(text, native)
        rows = [decode(line) for line in text.splitlines() if line.startswith('{')]
        other = [line for line in text.splitlines() if not line.startswith('{')]
        def rejected(label, changed, extra=other):
            nonlocal count
            path = output / (('native-' if native else 'guest-') + label + '.log')
            path.write_text('\n'.join(extra + [json.dumps(row, separators=(',', ':')) for row in changed]) + '\n')
            try:
                observations(path.read_text(), native)
            except (ValueError, KeyError, TypeError):
                count += 1
            else:
                raise ValueError('accepted damaged control evidence: ' + path.name)
        for number in range(157):
            changed = copy.deepcopy(rows)
            changed[number]['values'][number % 7] ^= 1
            rejected('value-' + str(number), changed)
        for number in (0, 6, 18, 58, 133, 142, 156):
            for key in ('result', 'errno', 'position', 'node', 'case'):
                changed = copy.deepcopy(rows)
                changed[number][key] += 1
                rejected(key + '-' + str(number), changed)
        rejected('missing', rows[:-1])
        rejected('duplicate', rows + [rows[0]])
        changed = copy.deepcopy(rows)
        changed[0]['unknown'] = 1
        rejected('unknown-field', changed)
        changed = copy.deepcopy(rows)
        changed[0]['position'] = True
        rejected('boolean-position', changed)
        changed = copy.deepcopy(rows)
        changed[0]['values'][0] = False
        rejected('boolean-value', changed)
        rejected('missing-completion', rows, [line for line in other if not line.startswith('IPV4_SOURCE_CONTROLS_PASS')])
        rejected('false-completion', rows, other + ['IPV4_SOURCE_CONTROLS_FAIL operation=write errno=1 case=157'])
        rejected('wrong-kernel', rows, [line.replace('sysname=Linux', 'sysname=Axiom64') if native else
                                      line.replace('sysname=Axiom64', 'sysname=Linux') for line in other])
        require(digest(log) == original, 'original successful evidence unchanged')
    result = dict(passed=True, serialized_reopened_controls=count, original_logs_unchanged=True)
    write(output / 'results.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify_controls(args.directory, args.output)), flush=True)


if __name__ == '__main__':
    main()

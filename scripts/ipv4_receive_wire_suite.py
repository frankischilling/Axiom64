# SPDX-License-Identifier: GPL-3.0-or-later
"""Run and independently verify three native and eight dual-adapter guest profiles."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from fetch import ROOT
from ipv4_native_capture_controls import damaged as cpu_damaged
from ipv4_receive_wire_contract import cohort, damaged, protected, verify
from ipv4_receive_wire_records import require
from tcp6.inputs import freeze


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv4-receive-wire')
    args = parser.parse_args()
    directory = (ROOT / args.directory).resolve()
    require(directory.is_relative_to((ROOT / 'build').resolve()), 'designated ignored output directory')
    directory.mkdir(parents=True, exist_ok=False)
    command = ['make', '-j2', *('build/ipv4-receive-wire-' + profile for profile in ('native', 'static', 'dynamic'))]
    (directory / 'build-command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (directory / 'build.log').open('xb') as output:
        subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    paths, values = [], []
    cases = [('linux-' + profile, ['--native', '--profile', profile]) for profile in ('native', 'static', 'dynamic')]
    cases += [(profile + '-' + firmware + '-' + transport,
               ['--profile', profile, '--firmware', firmware, '--transport', transport])
              for profile in ('static', 'dynamic') for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')]
    for name, arguments in cases:
        case = directory / name
        with (directory / (name + '.log')).open('xb') as output:
            process = subprocess.Popen([sys.executable, '-B', str(ROOT / 'scripts/ipv4_receive_wire_test.py'),
                *arguments, '--directory', str(case)], cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
            (directory / 'process.json').write_text(json.dumps(dict(pid=process.pid, case=name, status='running')) + '\n')
            code = process.wait()
            (directory / 'process.json').write_text(json.dumps(dict(pid=process.pid, case=name, status='completed', returncode=code)) + '\n')
        require(code == 0, 'actual metadata producer failed: ' + name)
        paths.append(case)
        values.append(verify(case))
        print('IPV4_RECEIVE_WIRE_PROFILE_PASS ' + name, flush=True)
    result = cohort(values)
    before = protected(paths)
    result['serialized_controls_rejected'] = damaged(directory / 'static-bios-modern', values,
                                                     directory / 'damaged-controls.zip')
    result['native_cpu_controls_rejected'] = cpu_damaged(directory / 'linux-native', directory / 'native-cpu-controls.zip', verify)
    require(protected(paths) == before, 'runtime evidence bytes, owners and modes remain exact')
    reader = directory / 'reader-source'
    reader.mkdir()
    result['reader_source'] = freeze(reader)
    result['source'] = values[0]['source']
    result['protected_inputs'] = before
    (directory / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    (directory / 'process.json').write_text(json.dumps(dict(status='completed', returncode=0)) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'protected_inputs'}), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

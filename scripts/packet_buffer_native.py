# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare packet receive-buffer options without changing host socket limits."""
import json
from pathlib import Path
import shutil
import subprocess
from build_musl import compiler_args, loader
from fetch import ROOT
from tcp_icmp_capture import audit_inputs, require
from tcp_icmp_inputs import record

SOURCES = ('Makefile', 'userspace/tests/net/packet.c', 'scripts/packet_buffer_native.py',
           'scripts/tcp_icmp_inputs.py', 'scripts/tcp_icmp_capture.py', 'scripts/build_musl.py')


def main():
    maximum = int(Path('/proc/sys/net/core/rmem_max').read_text())
    require(0 < maximum <= 0x3fffffff, 'actual native receive-buffer maximum bounds')
    subprocess.run(['make', 'build/net-tests'], cwd=ROOT, check=True)
    rows = []
    for linkage in ('native', 'static', 'dynamic'):
        binary = ROOT / 'build' / f'packet-buffer-{linkage}'
        if linkage == 'static':
            shutil.copyfile(ROOT / 'build/net-tests', binary)
            binary.chmod(0o755)
        else:
            compiler = ['gcc'] if linkage == 'native' else compiler_args('build')
            subprocess.run([*compiler, '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
                            '-pthread', str(ROOT / 'userspace/tests/net/packet.c'), '-o', str(binary)],
                           check=True)
        label = f'packet-buffer-linux-{linkage}'
        inputs = record(linkage, native=True, label=label, program='packet-buffer', sources=SOURCES)
        command = ([str(loader('build'))] if linkage == 'dynamic' else []) + [
            str(binary), 'buffer-options', str(maximum)]
        run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (ROOT / 'build' / (label + '.log')).write_bytes(run.stdout)
        require(run.returncode == 0 and run.stdout.decode().strip() ==
                f'PACKET_BUFFER_OPTIONS_PASS cases=9 maximum={maximum}', 'actual native option checks')
        audit_inputs(json.loads((ROOT / 'build' / inputs).read_text()))
        rows.append(dict(linkage=linkage, returncode=run.returncode, command=command,
                         rmem_max=maximum, host_limits_changed=False, cases=9,
                         inputs=inputs, log=label + '.log', passed=True))
    (ROOT / 'build/packet-buffer-native-results.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(json.dumps(dict(passed=True, profiles=len(rows), cases=27, host_limits_changed=False)))


if __name__ == '__main__':
    main()

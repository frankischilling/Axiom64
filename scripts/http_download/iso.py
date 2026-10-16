# SPDX-License-Identifier: GPL-3.0-or-later
"""Read actual boot components and configuration from a retained download ISO."""
import hashlib
from pathlib import Path
import subprocess
import tempfile

from tcp_fault_capture import require


def components(iso, expected):
    with tempfile.TemporaryDirectory(prefix='axiom64-download-iso-') as temporary:
        stage = Path(temporary)
        command = ['xorriso', '-osirrox', 'on', '-indev', str(iso)]
        for name in ('kernel.elf', 'root.cpio', 'limine.conf'):
            source = {'kernel.elf': '/boot/axiom64.elf', 'root.cpio': '/boot/rootfs.cpio',
                      'limine.conf': '/boot/limine/limine.conf'}[name]
            command += ['-extract', source, str(stage / name)]
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        inputs = {name: dict(bytes=(stage / name).stat().st_size,
                            sha256=hashlib.sha256((stage / name).read_bytes()).hexdigest())
                  for name in ('kernel.elf', 'root.cpio', 'limine.conf')}
        require(all(inputs[name] == value for name,value in expected.items()),
                'actual ISO contains exactly the retained kernel and checked initramfs')
        return dict(passed=True, files=inputs, configuration=(stage / 'limine.conf').read_text())

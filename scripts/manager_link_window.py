# SPDX-License-Identifier: GPL-3.0-or-later
"""Hold a received removal command before its actual guest observation."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time
from fetch import ROOT
from dhcp_peer import check
from tcp6.inputs import freeze


class RemovalWindow:
    def __init__(self, image, socket_path, label):
        self.directory = ROOT / 'build/manager-link-removal-evidence' / label
        self.directory.mkdir(parents=True, exist_ok=False)
        self.socket_path = socket_path
        self.armed = self.directory / 'armed.json'
        self.configured = self.directory / 'configured'
        self.release_path = self.directory / 'release'
        self.process = self.log = None
        self.removed_ns = self.released_ns = None
        self.source = freeze(self.directory)
        shutil.copyfile(image, self.directory / 'fixture.iso')
        with (self.directory / 'extraction.log').open('xb') as log:
            subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(image),
                            '-extract', '/boot/axiom64.elf', str(self.directory / 'kernel'),
                            '-extract', '/boot/rootfs.cpio', str(self.directory / 'root.cpio')],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        entries = {}
        with (self.directory / 'root.cpio').open('rb') as stream:
            while True:
                header = stream.read(110)
                check(len(header) == 110 and header[:6] == b'070701', 'actual removal fixture CPIO')
                fields = [int(header[6+n*8:14+n*8], 16) for n in range(13)]
                encoded = stream.read(fields[11])
                check(encoded[-1:] == b'\0', 'complete removal fixture name')
                name = encoded[:-1].decode(); stream.read(-stream.tell() % 4)
                body = stream.read(fields[6]); stream.read(-stream.tell() % 4)
                check(len(body) == fields[6], 'complete removal fixture member')
                if name == 'TRAILER!!!':
                    check(not any(stream.read()), 'complete removal fixture trailer')
                    break
                check(name not in entries, 'unique removal fixture member')
                entries[name] = body
        binary = ROOT / 'build/manager-link'
        data = binary.read_bytes()
        check(entries['bin/manager-link'] == data, 'actual debugger product is embedded in the ISO')
        for name in ('bin/manager-link', 'sbin/network-manager', 'sbin/network-manager-dynamic',
                     'sbin/init', 'lib/ld-musl-x86_64.so.1'):
            (self.directory / name.replace('/', '-')).write_bytes(entries[name])
        source = ROOT / 'userspace/tests/net/manager-link.cpp'
        sites = [i for i, line in enumerate(source.read_text().splitlines(), 1)
                 if line.strip() == 'command[used] = 0;']
        check(len(sites) == 1, 'unique complete serial-command boundary')
        location = subprocess.check_output(['gdb', '-q', '-batch', '-ex', 'file ' + str(binary),
            '-ex', f'info line userspace/tests/net/manager-link.cpp:{sites[0]}'], text=True)
        matches = re.findall(r'starts at address (0x[0-9a-f]+)', location)
        check(len(matches) == 1, 'actual executable has an observable command boundary')
        self.address = int(matches[0], 16)
        check(data[:7] == b'\x7fELF\2\1\1' and struct.unpack_from('<H', data, 18)[0] == 62,
              'actual x86-64 observer executable')
        offset = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
        check(size == 56 and offset + size*count <= len(data), 'complete observer program headers')
        code = None
        for at in range(offset, offset+size*count, size):
            kind, flags, start, virtual, physical, length, memory, alignment = struct.unpack_from('<IIQQQQQQ', data, at)
            if kind == 1 and virtual <= self.address and self.address+16 <= virtual+length:
                check(flags & 1 and length <= memory and start+length <= len(data),
                      'command boundary belongs to an actual executable load segment')
                code = data[start+self.address-virtual:start+self.address-virtual+16]
        check(code is not None, 'actual command boundary bytes exist')
        self.script = self.directory / 'window.gdb'
        self.script.write_text(f'''set pagination off
set confirm off
file {binary}
target remote {socket_path}
hbreak *{self.address:#x} if *(unsigned long long*){self.address:#x} == {int.from_bytes(code[:8],'little'):#x} && *(unsigned long long*){self.address+8:#x} == {int.from_bytes(code[8:],'little'):#x} && used == 4 && *(unsigned int*)command == 0x6e776f64
commands
silent
python
from pathlib import Path
import gdb,json,time
stage=gdb.parse_and_eval('command').string(length=int(gdb.parse_and_eval('used')))
failed=int(gdb.parse_and_eval('observer.capture_failed[observer.affected]'))
assert stage=='down' and failed==0
assert bool(gdb.parse_and_eval('observer.disabled')) and bool(gdb.parse_and_eval('observer.failed'))
Path({str(self.armed)!r}).write_text(json.dumps(dict(command=stage,capture_failed=failed,pc=int(gdb.parse_and_eval('$pc')),host_monotonic_ns=time.monotonic_ns())))
deadline=time.monotonic()+20
while not Path({str(self.release_path)!r}).exists():
    assert time.monotonic()<deadline,'Host did not release the actual removal command'
    time.sleep(.005)
end
disable 1
detach
quit
end
python
from pathlib import Path
Path({str(self.configured)!r}).write_text('actual breakpoint configured\\n')
end
continue
''')
        products = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in self.directory.iterdir() if path.is_file()}
        self.before = dict(source=self.source, products=products, address=self.address,
                           code_bytes=code.hex(), no_guest_memory_register_or_clock_writes=True)
        (self.directory / 'preexecution.json').write_text(json.dumps(self.before, indent=2) + '\n')

    def arguments(self):
        return ['-chardev', f'socket,path={self.socket_path},server=on,wait=off,id=removal-window',
                '-gdb', 'chardev:removal-window']

    def start(self):
        self.log = (self.directory / 'debugger.log').open('xb')
        self.process = subprocess.Popen(['gdb', '-q', '-batch', '-x', str(self.script)],
                                        stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 5
        while not self.configured.exists():
            check(self.process.poll() is None and time.monotonic() < deadline,
                  'actual removal-command breakpoint becomes available')
            time.sleep(.005)

    def remove_and_release(self, hardware):
        deadline = time.monotonic() + 5
        while not self.armed.exists():
            check(self.process.poll() is None and time.monotonic() < deadline,
                  'guest receives the complete original down command')
            time.sleep(.005)
        observed = json.loads(self.armed.read_text())
        check(observed['command'] == 'down' and observed['capture_failed'] == 0 and
              observed['pc'] == self.address, 'actual stale capture precedes command evaluation')
        hardware.remove(resume=False)
        self.removed_ns = time.monotonic_ns()
        self.release_path.write_text('actual PCI deletion completed before guest command evaluation\n')
        self.released_ns = time.monotonic_ns()

    def close(self):
        if self.process is not None and self.process.poll() is None:
            if not self.release_path.exists():
                self.release_path.write_text('release after failed fixture\n')
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        if self.log is not None:
            self.log.close()
        valid = (self.process is not None and self.process.returncode == 0 and
                 self.armed.exists() and self.removed_ns is not None and self.released_ns is not None)
        if valid:
            valid = json.loads(self.armed.read_text())['host_monotonic_ns'] <= self.removed_ns <= self.released_ns
        for name, expected in self.before['products'].items():
            valid = valid and hashlib.sha256((self.directory / name).read_bytes()).hexdigest() == expected
        self.valid = valid
        (self.directory / 'receipt.json').write_text(json.dumps(dict(
            passed=valid, observed=json.loads(self.armed.read_text()) if self.armed.exists() else None,
            removed_ns=self.removed_ns, released_ns=self.released_ns,
            returncode=None if self.process is None else self.process.returncode,
            source=self.source, original_products_unchanged=valid), indent=2) + '\n')

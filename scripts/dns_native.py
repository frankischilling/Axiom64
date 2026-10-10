# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare real musl DNS in a private Linux mount/network namespace."""
import json
import hashlib
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time
from fetch import ROOT
from dns_peer import Answers, check


class NativePeer(Answers):
    def __init__(self, lane, selector):
        super().__init__(lane)
        self.ip = f'10.23.{lane + 1}.1'
        self.sockets = {}
        for kind, address, port in [('answer', self.ip, 53), ('wrong-port', self.ip, 54),
                                    ('wrong-source', f'10.23.{lane + 1}.9', 53)]:
            channel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            channel.bind((address, port))
            channel.setblocking(False)
            self.sockets[kind] = channel
            if kind == 'answer':
                selector.register(channel, selectors.EVENT_READ, self)

    def send(self, sender, data, kind='answer'):
        channel = self.sockets.get(kind, self.sockets['answer'])
        check(channel.sendto(data, sender) == len(data), 'native DNS datagram transmission')
        self.replies.append(dict(kind=kind, data=data.hex(), sender=list(sender)))

    def close(self):
        for channel in self.sockets.values():
            channel.close()


def namespace(scratch):
    parent = json.loads((scratch / 'parent-namespaces.json').read_text())
    check(all(os.readlink('/proc/self/ns/' + kind) != parent[kind] for kind in ('mnt', 'net')),
          'fixture resolver mounts and addresses require isolated mount and network namespaces')
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    for name in ('resolv.conf', 'hosts'):
        subprocess.run(['mount', '--bind', str(scratch / name), '/etc/' + name], check=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    for lane in range(2):
        for host in (1, 9):
            subprocess.run(['ip', 'addr', 'add', f'10.23.{lane + 1}.{host}/32', 'dev', 'lo'], check=True)
    selector = selectors.DefaultSelector()
    peers = [NativePeer(lane, selector) for lane in range(2)]
    logs = []
    try:
        for linkage in ('static', 'dynamic'):
            output = scratch / f'dns-native-{linkage}.log'
            with output.open('wb') as stream:
                process = subprocess.Popen([str(ROOT / 'build' / f'dns-{linkage}'), '--native'],
                                            stdout=stream, stderr=subprocess.STDOUT)
                started = time.monotonic()
                try:
                    while process.poll() is None:
                        check(time.monotonic() - started < 20, 'bounded native DNS comparison')
                        for peer in peers:
                            peer.tick()
                        for key, _ in selector.select(.005):
                            data, sender = key.fileobj.recvfrom(65535)
                            key.data.receive(data, sender)
                finally:
                    if process.poll() is None:
                        process.kill()
                    status = process.wait()
            text = output.read_text()
            print(text, end='', flush=True)
            check(status == 0 and f'DNS_TESTS_PASS linkage={linkage} cases=17 threads=8 cycles=128' in text,
                  'complete native resolver contract')
            logs.append(text)
        evidence = dict(passed=True, peers=[peer.validate() for peer in peers], logs=logs,
                        parent_namespaces=parent,
                        fixture_namespaces={kind: os.readlink('/proc/self/ns/' + kind) for kind in ('mnt', 'net')})
        (scratch / 'native-results.json').write_text(json.dumps(evidence, indent=2) + '\n')
    finally:
        selector.close()
        for peer in peers:
            peer.close()


def run():
    check(os.geteuid() == 0, 'native DNS namespaces require root privileges')
    original = {name: hashlib.sha256(Path('/etc/' + name).read_bytes()).hexdigest()
                for name in ('resolv.conf', 'hosts')}
    subprocess.run(['make', '-s', 'build/dns-static', 'build/dns-dynamic'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='axiom64-dns-native-') as directory:
        scratch = Path(directory)
        (scratch / 'resolv.conf').write_text('nameserver 10.23.1.1\n')
        (scratch / 'hosts').write_text('10.23.1.100 local-host.fixture\n')
        (scratch / 'parent-namespaces.json').write_text(json.dumps({
            kind: os.readlink('/proc/self/ns/' + kind) for kind in ('mnt', 'net')}))
        result = subprocess.run(['unshare', '--mount', '--net', '--fork', sys.executable,
                                 __file__, '--namespace', str(scratch)],
                                capture_output=True, text=True, timeout=45)
        (ROOT / 'build/dns-native.log').write_text(result.stdout + result.stderr)
        print(result.stdout, end='', flush=True)
        if result.returncode:
            print(result.stderr, end='', flush=True)
        check(result.returncode == 0, 'isolated native Linux DNS comparison')
        evidence = json.loads((scratch / 'native-results.json').read_text())
        current = {name: hashlib.sha256(Path('/etc/' + name).read_bytes()).hexdigest()
                   for name in ('resolv.conf', 'hosts')}
        check(current == original, 'native fixtures preserve original host resolver and hosts bytes')
        check(all(evidence['parent_namespaces'][kind] != evidence['fixture_namespaces'][kind]
                  for kind in ('mnt', 'net')), 'reported namespace isolation')
        evidence['host_files_unchanged_sha256'] = original
        (ROOT / 'build/dns-native-results.json').write_text(json.dumps(evidence, indent=2) + '\n')
        return evidence


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--namespace':
        namespace(Path(sys.argv[2]))
    else:
        run()

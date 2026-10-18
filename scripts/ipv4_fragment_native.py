# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the actual fragment client on Linux through private TAP Ethernet peers."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import struct
import subprocess
import sys
import time
from build_musl import loader
from fetch import ROOT
from ipv4_fragments import FragmentPeer
from tcp_fault_native import Capture


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def client(profile):
    binary = ROOT / 'build' / {'native': 'ipv4-native', 'static': 'ipv4-tests',
                              'dynamic': 'ipv4-dynamic'}[profile]
    command = [str(binary), '--fragments']
    if profile == 'dynamic':
        command.insert(0, str(loader('build')))
    return command


def child(profile, directory):
    directory.mkdir(exist_ok=False)
    peers = [FragmentPeer(lane) for lane in range(2)]
    taps, captures, statistics, links = [], [], [], []
    process = None
    error = None
    command = client(profile)
    sources = ['userspace/tests/net/ipv4.c', 'userspace/tests/net/ipv4_fragments.c',
               'userspace/tests/net/ipv4_fragments.h', 'scripts/ipv4_fragments.py',
               'scripts/ipv4_fragment_native.py', 'scripts/tcp_fault_native.py', 'Makefile']
    before = dict(profile=profile, kernel=platform.uname()._asdict(), command=command,
                  source_sha256={name: digest(ROOT / name) for name in sources},
                  executable_sha256={name: digest(Path(name)) for name in command[:-1]},
                  namespace_linkage='private network namespace; two private TAP devices')
    (directory / 'preexecution.json').write_text(json.dumps(before, indent=2) + '\n')
    products = directory / 'products'
    products.mkdir(exist_ok=False)
    for position, name in enumerate(command[:-1]):
        copied = products / f'{position}-{Path(name).name}'
        shutil.copy2(name, copied)
        if digest(copied) != before['executable_sha256'][name]:
            raise ValueError('native product changed while preserving its original bytes')
    started = time.monotonic()
    selector = selectors.DefaultSelector()
    try:
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        for lane in range(2):
            name = f'eth{lane}'
            descriptor = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            taps.append(descriptor)
            fcntl.ioctl(descriptor, 0x400454ca, struct.pack('16sH', name.encode(), 0x1002))
            guest_mac = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
            subprocess.run(['ip', 'link', 'set', 'dev', name, 'address', guest_mac.hex(':'),
                            'mtu', '1500', 'txqueuelen', '8192', 'up'], check=True)
            selector.register(descriptor, selectors.EVENT_READ, lane)
            captures.append(Capture(name, directory / f'lane{lane}.pcap'))
        with (directory / 'client.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL, cwd=ROOT)
            while True:
                if time.monotonic() - started > 30:
                    raise TimeoutError('fragment comparison exceeded its 30-second bound')
                if process.poll() not in (None, 0):
                    raise RuntimeError(f'fragment client exited {process.returncode}')
                for key, _ in selector.select(.02):
                    lane = key.data
                    frame = os.read(key.fd, 65535)
                    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
                    mac = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
                    local = bytes([10, 23, lane + 1, 2])
                    remote = bytes([10, 23, lane + 1, 1])
                    if len(frame) >= 42 and frame[12:14] == b'\x08\x06':
                        if frame[20:22] != b'\0\x01' or frame[38:42] != remote:
                            continue
                        if (frame[14:20] != b'\0\x01\x08\0\x06\x04' or
                                frame[6:12] != guest or frame[22:32] != guest + local):
                            raise ValueError('native ARP source or wire shape differs')
                        response = (guest + mac + b'\x08\x06' +
                                    struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2) +
                                    mac + remote + guest + local).ljust(60, b'\0')
                        if os.write(key.fd, response) != len(response):
                            raise OSError('short TAP ARP injection')
                    elif len(frame) >= 34 and frame[12:14] == b'\x08\0':
                        packet = frame[14:]
                        total = int.from_bytes(packet[2:4], 'big')
                        packet = packet[:total]
                        if not peers[lane].accepts(packet):
                            continue
                        if frame[:12] != mac + guest:
                            raise ValueError('native fragment control Ethernet ownership differs')
                        if total > len(packet):
                            raise ValueError('truncated native control packet')
                        for payload in peers[lane].receive(packet[:total]):
                            response = guest + mac + b'\x08\0' + payload
                            if os.write(key.fd, response) != len(response):
                                raise OSError('short TAP fragment injection')
                if process.poll() == 0 and all(peer.acknowledged and peer.output.acknowledged for peer in peers):
                    break
    except Exception as exception:
        error = f'{type(exception).__name__}: {exception}'
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for capture in captures:
            try:
                statistics.append(capture.close())
            except Exception as exception:
                error = error or f'capture: {exception}'
        for lane in range(len(taps)):
            try:
                row = json.loads(subprocess.check_output(
                    ['ip', '-s', '-j', 'link', 'show', 'dev', f'eth{lane}']))[0]
                links.append(row)
                counts = row['stats64']
                if counts['tx']['dropped'] or counts['rx']['dropped']:
                    error = error or 'native TAP reports dropped frames'
            except Exception as exception:
                error = error or f'TAP statistics: {exception}'
        (directory / 'links-final.json').write_text(json.dumps(links, indent=2) + '\n')
        selector.close()
        for descriptor in taps:
            os.close(descriptor)
    text = (directory / 'client.log').read_text(errors='replace') if process else ''
    completed = [peer.completed for peer in peers]
    acknowledged = [peer.acknowledged for peer in peers]
    output_cases = [peer.output.completed for peer in peers]
    output_ack = [peer.output.acknowledged for peer in peers]
    markers = all(f'IPV4_FRAGMENT_PASS index={lane + 1} cases=6\n' in text for lane in range(2))
    markers = markers and all(f'IPV4_FRAGMENT_OUTPUT_PASS index={lane + 1} cases=21\n' in text
                              for lane in range(2))
    result = dict(profile=profile, error=error, returncode=process.returncode if process else None,
                  cases=completed, final_ack=acknowledged, frames=[peer.frames for peer in peers],
                  output_cases=output_cases, output_final_ack=output_ack,
                  output_frames=[peer.output.frames for peer in peers],
                  link_statistics=links,
                  seconds=time.monotonic() - started, capture_statistics=statistics,
                  source_sha256=before['source_sha256'],
                  passed=(error is None and process is not None and process.returncode == 0 and
                          completed == [6, 6] and all(acknowledged) and output_cases == [21, 21] and
                          all(output_ack) and markers and len(statistics) == 2))
    (directory / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return result['passed']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv4-fragments-native')
    parser.add_argument('--child', choices=['native', 'static', 'dynamic'])
    args = parser.parse_args()
    directory = args.directory.resolve()
    if directory == (ROOT / 'build').resolve() or not directory.is_relative_to((ROOT / 'build').resolve()):
        raise ValueError('native evidence must have a dedicated directory beneath build/')
    if args.child:
        return 0 if child(args.child, directory) else 1
    directory.mkdir(parents=True, exist_ok=False)
    with (directory / 'build.log').open('wb') as log:
        built = subprocess.run(['make', '-j2', 'build/ipv4-native', 'build/ipv4-tests',
                                'build/ipv4-dynamic'], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    results = []
    if built.returncode == 0:
        for profile in ['native', 'static', 'dynamic']:
            completed = subprocess.run(['unshare', '--net', sys.executable, __file__, '--child', profile,
                                        '--directory', str(directory / profile)], cwd=ROOT)
            results.append(dict(profile=profile, returncode=completed.returncode))
    passed = built.returncode == 0 and len(results) == 3 and all(row['returncode'] == 0 for row in results)
    (directory / 'receipt.json').write_text(json.dumps(dict(passed=passed,
        build_returncode=built.returncode, profiles=results), indent=2) + '\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

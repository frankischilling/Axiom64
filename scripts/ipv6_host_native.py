# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the actual IPv6 control client on isolated native Ethernet links."""
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
from compile_uapi_client import audit_compile
from fetch import ROOT
from ipv6_host_peer import Peer
from ipv6_host_capture import verify_capture
from tcp_fault_native import Capture


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def child(profile, directory):
    directory.mkdir(exist_ok=False)
    program = ROOT / 'build' / ('ipv6-host-' + profile)
    command = [str(program)]
    if profile == 'dynamic':
        command.insert(0, str(loader('build')))
    sources = {name: digest(ROOT / name) for name in (
        'userspace/tests/net/ipv6_host.c', 'scripts/ipv6_host_native.py',
        'scripts/ipv6_host_peer.py', 'scripts/ipv6_host_capture.py', 'scripts/tcp_fault_native.py')}
    products = {name: digest(Path(name)) for name in command}
    saved = directory / 'products'
    saved.mkdir()
    for n, name in enumerate(command):
        shutil.copy2(name, saved / f'{n}-{Path(name).name}')
    if profile != 'native':
        audit_compile(program, ROOT)
        shutil.copy2(program.with_suffix('.inputs.json'), saved / 'compile.inputs.json')
    settings = {
        'net.ipv6.conf.all.disable_ipv6': 0, 'net.ipv6.conf.default.disable_ipv6': 0,
        'net.ipv6.conf.default.addr_gen_mode': 1,
        'net.ipv6.conf.all.accept_ra': 0, 'net.ipv6.conf.default.accept_ra': 0,
        'net.ipv6.conf.all.autoconf': 0, 'net.ipv6.conf.default.autoconf': 0,
        'net.ipv6.conf.all.enhanced_dad': 0, 'net.ipv6.conf.default.enhanced_dad': 0,
        'net.ipv6.auto_flowlabels': 0,
    }
    for name, value in settings.items():
        subprocess.run(['sysctl', '-q', '-w', f'{name}={value}'], check=True)
    (directory / 'preexecution.json').write_text(json.dumps(dict(profile=profile,
        kernel=platform.uname()._asdict(), command=command, settings=settings,
        source_sha256=sources, product_sha256=products), indent=2) + '\n')
    peers = [Peer(lane, native=True) for lane in range(2)]
    taps, captures, statistics = [], [], []
    selector = selectors.DefaultSelector()
    process, error = None, None
    began = time.monotonic()
    try:
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        for lane in range(2):
            tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            taps.append(tap)
            name = f'eth{lane}'
            fcntl.ioctl(tap, 0x400454ca, struct.pack('16sH', name.encode(), 0x1002))
            subprocess.run(['ip', 'link', 'set', 'dev', name, 'address',
                            peers[lane].guest.hex(':'), 'mtu', '1500', 'up'], check=True)
            selector.register(tap, selectors.EVENT_READ, lane)
            captures.append(Capture(name, directory / f'lane{lane}.pcap'))
        with (directory / 'client.log').open('wb') as output:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT)
            while process.poll() is None:
                if time.monotonic() - began > 45:
                    raise TimeoutError('native IPv6 client exceeded its overall deadline')
                for key, _ in selector.select(.02):
                    peers[key.data].receive(os.read(key.fd, 65535))
                for lane, peer in enumerate(peers):
                    while peer.outgoing:
                        packet = peer.outgoing.pop(0)
                        if os.write(taps[lane], packet) != len(packet):
                            raise OSError('short native IPv6 Ethernet injection')
            if process.returncode:
                raise ValueError(f'actual native client exited {process.returncode}')
    except Exception as failure:
        error = f'{type(failure).__name__}: {failure}'
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
            except Exception as failure:
                error = error or f'capture: {failure}'
        selector.close()
        for tap in taps:
            os.close(tap)
    audits = []
    if not error and all(peer.passed for peer in peers):
        try:
            for lane in range(2):
                audits.append(verify_capture(directory / f'lane{lane}.pcap', lane,
                    directory / 'client.log', directory / f'lane{lane}-damaged.zip', native=True))
        except Exception as failure:
            error = f'independent native capture: {failure}'
    unchanged = all(digest(ROOT / name) == value for name, value in sources.items())
    unchanged &= all(digest(Path(name)) == value for name, value in products.items())
    passed = (not error and process is not None and process.returncode == 0 and unchanged and
              all(peer.passed for peer in peers) and len(audits) == 2 and
              len(statistics) == 2 and all(not row['dropped'] for row in statistics))
    result = dict(passed=passed, profile=profile, seconds=time.monotonic() - began,
                  returncode=process.returncode if process else None, error=error,
                  source_products_unchanged=unchanged, peers=[peer.result() for peer in peers],
                  capture_audits=audits, capture_statistics=statistics,
                  settings=settings, full_F12_complete=False)
    (directory / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('peers', 'settings')}), flush=True)
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--child', choices=('native', 'static', 'dynamic'))
    parser.add_argument('--profile', choices=('native', 'static', 'dynamic', 'all'), default='all')
    parser.add_argument('--output-directory', type=Path, default=ROOT / 'build/ipv6-host-native-wire')
    args = parser.parse_args()
    if args.child:
        return child(args.child, args.output_directory)
    profiles = ('native', 'static', 'dynamic') if args.profile == 'all' else (args.profile,)
    subprocess.run(['make', '-j2', *('build/ipv6-host-' + profile for profile in profiles)], cwd=ROOT, check=True)
    args.output_directory.mkdir(parents=True, exist_ok=True)
    results = []
    for profile in profiles:
        directory = args.output_directory / profile
        result = subprocess.run(['unshare', '--net', sys.executable, '-B', 'scripts/ipv6_host_native.py',
                                 '--child', profile, '--output-directory', str(directory)], cwd=ROOT)
        results.append(dict(profile=profile, returncode=result.returncode))
    (args.output_directory / 'receipt.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0 if all(not row['returncode'] for row in results) else 1


if __name__ == '__main__':
    sys.exit(main())

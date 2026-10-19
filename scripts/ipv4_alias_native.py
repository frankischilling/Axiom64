# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare IPv4 address and gateway clients on isolated native Ethernet links."""
import argparse
from concurrent.futures import ThreadPoolExecutor
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
from ipv4_aliases import AliasPeer
from ipv4_alias_capture import verify_capture as verify_alias_capture
from ipv4_gateways import GatewayPeer
from ipv4_gateway_capture import verify_capture as verify_gateway_capture
from ipv4_unconfigured_capture import verify_capture as verify_unconfigured_capture
from ipv4_query_model import query_model
from tcp_fault_native import Capture

SOURCES = ('Makefile', 'userspace/tests/net/ipv4.c', 'userspace/tests/net/ipv4_aliases.c',
           'userspace/tests/net/ipv4_aliases.h', 'scripts/ipv4_aliases.py',
           'scripts/ipv4_alias_capture.py', 'scripts/ipv4_path_mtu_capture.py',
           'userspace/tests/net/ipv4_fragments.c', 'userspace/tests/net/ipv4_fragments.h',
           'userspace/tests/net/ipv4_path_mtu.c', 'userspace/tests/net/ipv4_path_mtu.h',
           'scripts/ipv4_alias_native.py', 'scripts/tcp_fault_native.py', 'scripts/build_musl.py',
           'scripts/compile_uapi_client.py', 'scripts/linux_uapi.py', 'scripts/build_openssl.py',
           'ports.lock.json', 'userspace/tests/net/ipv4_gateways.c',
           'userspace/tests/net/ipv4_gateways.h', 'scripts/ipv4_gateways.py',
           'scripts/ipv4_gateway_capture.py', 'scripts/ipv4_query_model.py',
           'userspace/tests/net/ipv4_query.h', 'userspace/tests/net/ipv4_unconfigured.c',
           'userspace/tests/net/ipv4_unconfigured.h', 'scripts/ipv4_unconfigured.py',
           'scripts/ipv4_unconfigured_capture.py')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def child(profile, directory, suite='aliases'):
    directory.mkdir(exist_ok=False)
    binary = ROOT / 'build' / {'native': 'ipv4-native', 'static': 'ipv4-tests',
                              'dynamic': 'ipv4-dynamic'}[profile]
    command = [str(binary), '--' + suite]
    if profile == 'dynamic':
        command.insert(0, str(loader('build')))
    sources = {name: digest(ROOT / name) for name in SOURCES}
    model = query_model(platform.uname()._asdict())
    products = {name: digest(Path(name)) for name in command[:-1]}
    (directory / 'preexecution.json').write_text(json.dumps(dict(command=command,
        kernel=platform.uname()._asdict(), query_model=model, source_sha256=sources,
        executable_sha256=products), indent=2) + '\n')
    saved = directory / 'products'
    saved.mkdir()
    for n, name in enumerate(command[:-1]):
        target = saved / f'{n}-{Path(name).name}'
        shutil.copy2(name, target)
        if digest(target) != products[name]:
            raise ValueError('alias executable changed during preservation')
    if profile != 'native':
        inputs = binary.with_suffix('.inputs.json')
        audit_compile(binary, ROOT)
        shutil.copy2(inputs, saved / 'compile.inputs.json')
    peers = [(GatewayPeer if suite == 'gateways' else AliasPeer)(lane) for lane in range(2)]
    selector = selectors.DefaultSelector()
    taps, captures, statistics, links = [], [], [], []
    process, error = None, None
    started = time.monotonic()
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
        with (directory / 'client.log').open('wb') as log:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT)
            while process.poll() is None:
                if time.monotonic() - started > 30:
                    raise TimeoutError('alias comparison exceeded 30 seconds')
                for key, _ in selector.select(.02):
                    frame = os.read(key.fd, 65535)
                    replies = peers[key.data].receive(frame)
                    for reply in replies or []:
                        if os.write(key.fd, reply) != len(reply):
                            raise OSError('short alias TAP injection')
            if process.returncode:
                raise RuntimeError(f'alias client exited {process.returncode}')
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
                link = json.loads(subprocess.check_output(
                    ['ip', '-s', '-j', 'link', 'show', 'dev', f'eth{lane}']))[0]
                links.append(link)
                counts = link['stats64']
                if counts['tx']['dropped'] or counts['rx']['dropped']:
                    error = error or 'alias TAP dropped frames'
            except Exception as exception:
                error = error or f'link statistics: {exception}'
        selector.close()
        for tap in taps:
            os.close(tap)
    text = (directory / 'client.log').read_text(errors='replace') if process else ''
    audits = []
    if error is None and process is not None and process.returncode == 0 and all(p.passed for p in peers):
        try:
            for lane in range(2):
                archive = directory / f'lane{lane}-{"gateway" if suite == "gateways" else "alias"}-damaged.zip'
                if suite == 'gateways':
                    audits.append(verify_gateway_capture(directory / f'lane{lane}.pcap', lane,
                        directory / 'client.log', archive, native=True, query_model=model))
                    audits.append(verify_unconfigured_capture(directory / f'lane{lane}.pcap', lane,
                        directory / 'client.log', directory / f'lane{lane}-unconfigured-damaged.zip',
                        native=True))
                else:
                    audits.append(verify_alias_capture(directory / f'lane{lane}.pcap', lane,
                        directory / 'client.log', archive, query_model=model))
        except Exception as exception:
            error = f'alias capture audit: {exception}'
    unchanged = all(digest(ROOT / n) == value for n, value in sources.items())
    products_unchanged = all(digest(Path(name)) == value for name, value in products.items())
    marker = ('IPV4_GATEWAY_PASS index={index} protocols=2 datagrams=12\n' if suite == 'gateways' else
              'IPV4_ALIAS_PASS index={index} wire_cases=4 local_udp=3\n')
    passed = (error is None and process is not None and process.returncode == 0 and
              unchanged and products_unchanged and len(audits) == (4 if suite == 'gateways' else 2) and all(a['passed'] for a in audits) and len(statistics) == 2 and all(not s['dropped'] for s in statistics) and
              all(peer.passed for peer in peers) and all(
                  marker.format(index=lane + 1) in text
                  for lane in range(2)) and (suite != 'gateways' or all(
                  f'IPV4_UNCONFIGURED_PASS index={lane + 1} protocols=2 datagrams=14\n' in text
                  for lane in range(2))))
    result = dict(passed=passed, profile=profile, suite=suite, error=error, source_unchanged=unchanged,
                  products_unchanged=products_unchanged,
                  returncode=process.returncode if process else None,
                  peers=[p.report() if suite == 'gateways' else
                         dict(cases=p.cases, arp_requests=p.arp_requests, arp_replies=p.arp_replies,
                              kernel_replies=p.kernel_replies, passed=p.passed) for p in peers],
                  capture_audits=audits, capture_statistics=statistics, link_statistics=links,
                  seconds=time.monotonic() - started)
    (directory / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in
                      ('capture_statistics', 'link_statistics')}), flush=True)
    return passed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--suite', choices=('aliases', 'gateways'), default='aliases')
    parser.add_argument('--child', choices=['native', 'static', 'dynamic'])
    args = parser.parse_args()
    directory = (args.directory or ROOT / f'build/ipv4-{args.suite}-native').resolve()
    if directory == (ROOT / 'build').resolve() or not directory.is_relative_to((ROOT / 'build').resolve()):
        raise ValueError('alias evidence needs a dedicated directory beneath build/')
    if args.child:
        return 0 if child(args.child, directory, args.suite) else 1
    directory.mkdir(parents=True, exist_ok=False)
    with (directory / 'build.log').open('wb') as log:
        built = subprocess.run(['make', '-j2', 'build/ipv4-native', 'build/ipv4-tests',
                                'build/ipv4-dynamic'], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    results = []
    if not built.returncode:
        def compare(profile):
            result = subprocess.run(['unshare', '--net', sys.executable, __file__, '--child', profile,
                                     '--suite', args.suite,
                                     '--directory', str(directory / profile)], cwd=ROOT)
            return dict(profile=profile, returncode=result.returncode)
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(compare, ['native', 'static', 'dynamic']))
    passed = not built.returncode and len(results) == 3 and all(not row['returncode'] for row in results)
    (directory / 'receipt.json').write_text(json.dumps(dict(passed=passed,
        suite=args.suite, build_returncode=built.returncode, profiles=results), indent=2) + '\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

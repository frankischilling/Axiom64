# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare packet protocol listeners with three isolated native Linux linkages."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import socket
import subprocess
import sys
import time

from build_musl import loader
from compile_uapi_client import audit_compile, sources
from fetch import ROOT
from network_test import packet_protocol_observations, reply
from tcp_fault_native import Capture

SOURCE = 'userspace/tests/net/packet.c'
HELPERS = ('scripts/packet_protocol_native.py', 'scripts/network_test.py',
           'scripts/tcp_fault_native.py', 'scripts/tcp_capture_clock.py',
           'scripts/compile_uapi_client.py', 'scripts/build_musl.py', 'ports.lock.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def child(args):
    namespace = Path('/proc/self/ns/net').stat().st_ino
    require(namespace != args.parent_namespace, 'packet comparison requires its own network namespace')
    args.directory.mkdir()
    program = args.program.resolve()
    manifest = audit_compile(program, ROOT)
    before = {name: digest(ROOT / name) for name in (*HELPERS, *manifest['sources'])}
    for scope in ('all', 'default'):
        Path(f'/proc/sys/net/ipv6/conf/{scope}/disable_ipv6').write_text('1\n')
    channels, captures, peers = [], [], [[], []]
    indices, statistics, monitor_errors = [], [], []
    selector = selectors.DefaultSelector()
    command = ([str(loader('build'))] if args.linkage == 'dynamic' else []) + [
        str(program), 'protocol-selection']
    process = None
    error = None
    began = time.monotonic()
    log = args.directory / 'serial.log'
    try:
        for lane in range(2):
            for setup in (
                ['ip', 'link', 'add', f'eth{lane}', 'type', 'veth', 'peer', 'name', f'peer{lane}'],
                ['ip', 'link', 'set', f'eth{lane}', 'address', f'52:54:00:12:34:{16 + lane:02x}'],
                ['ip', 'link', 'set', f'peer{lane}', 'address', f'02:41:58:50:4b:{lane:02x}', 'up']):
                subprocess.run(setup, check=True)
            indices.append(socket.if_nametoindex(f'eth{lane}'))
            channel = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88b5))
            channel.bind((f'peer{lane}', 0))
            channel.setblocking(False)
            channels.append(channel)
            selector.register(channel, selectors.EVENT_READ, lane)
            captures.append(Capture(f'peer{lane}', args.directory / f'lane{lane}.pcap'))
        with log.open('wb') as output:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT)
            while process.poll() is None:
                require(time.monotonic() - began < 45, 'finite native packet protocol comparison')
                for key, _ in selector.select(.005):
                    lane = key.data
                    frame = channels[lane].recv(1600)
                    require(not peers[lane], 'one original native protocol exchange per interface')
                    response = reply(frame, lane)
                    require(channels[lane].send(response) == len(response), 'complete native peer reply')
                    peers[lane].append(dict(frame=frame.hex(), reply=response.hex(),
                                            observed_monotonic_ns=time.monotonic_ns()))
    except (ValueError, OSError) as failure:
        error = str(failure)
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
        selector.close()
        for channel in channels:
            channel.close()
        for capture in captures:
            try:
                statistics.append(capture.close())
            except (ValueError, OSError) as failure:
                statistics.append(None)
                monitor_errors.append(str(failure))
    text = log.read_text() if log.is_file() else ''
    unchanged = all(digest(ROOT / name) == value for name, value in before.items())
    protocol = packet_protocol_observations(text, indices)
    passed = (error is None and process is not None and process.returncode == 0 and unchanged and
              not monitor_errors and len(statistics) == 2 and all(len(values) == 1 for values in peers) and
              text.splitlines().count('PACKET_PROTOCOL_SELECTION_PASS lanes=2') == 1 and
              protocol['passed'] and 'PACKET_FAIL' not in text and
              all(value['dropped'] == 0 and value['receipt_frames'] == 2 for value in statistics))
    receipt = dict(passed=passed, linkage=args.linkage, command=command,
                   returncode=process.returncode if process else None, error=error,
                   seconds=time.monotonic() - began, kernel_release=platform.release(),
                   network_namespace=namespace, parent_network_namespace=args.parent_namespace,
                   protocol_observations=protocol,
                   indices=indices, client_sha256=digest(program),
                   interpreter_sha256=digest(Path(command[0])) if args.linkage == 'dynamic' else None,
                   log_sha256=digest(log) if log.is_file() else None,
                   source_inputs=before, source_unchanged=unchanged, captures=statistics,
                   packet_monitor_errors=monitor_errors, peer_reports=peers, clock_acceptance=False)
    (args.directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/packet-protocol-native')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--program', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--linkage', choices=('native', 'static', 'dynamic'), help=argparse.SUPPRESS)
    parser.add_argument('--parent-namespace', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.directory = args.directory.resolve()
    if args.child:
        require(args.program is not None and args.linkage is not None and args.parent_namespace is not None,
                'explicit native packet comparison inputs')
        raise SystemExit(0 if child(args)['passed'] else 1)
    require(os.geteuid() == 0, 'native packet protocol comparison needs isolated privileged namespaces')
    args.directory.mkdir(parents=True)
    rows = []
    for linkage in ('native', 'static', 'dynamic'):
        program = args.directory / ('packet-' + linkage)
        flags = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread', SOURCE]
        if linkage == 'native':
            command = ['gcc', *flags, '-o', str(program)]
            inputs = sources(command, ROOT)
            subprocess.run(command, cwd=ROOT, check=True)
            require(inputs == sources(command, ROOT), 'native packet source changed during compilation')
            program.with_suffix('.inputs.json').write_text(json.dumps(dict(command=command,
                sources=inputs, compiler='host gcc/glibc', product=dict(sha256=digest(program),
                bytes=program.stat().st_size)), indent=2) + '\n')
        else:
            subprocess.run([sys.executable, 'scripts/compile_uapi_client.py', '--output', str(program),
                            '--', *flags, *(['-static'] if linkage == 'static' else [])], cwd=ROOT, check=True)
        audit_compile(program, ROOT)
        case = args.directory / linkage
        launch = ['unshare', '--net', '--fork', sys.executable, str(Path(__file__).resolve()),
                  '--child', '--directory', str(case), '--program', str(program), '--linkage', linkage,
                  '--parent-namespace', str(Path('/proc/self/ns/net').stat().st_ino)]
        with (args.directory / (linkage + '-launcher.log')).open('wb') as stream:
            result = subprocess.run(launch, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
        receipt = json.loads((case / 'receipt.json').read_text()) if (case / 'receipt.json').is_file() else dict(passed=False)
        receipt['passed'] &= result.returncode == 0
        rows.append(receipt)
        print('PACKET_PROTOCOL_NATIVE', linkage, receipt['passed'], flush=True)
    proof = dict(passed=all(row['passed'] for row in rows), profiles=len(rows), reports=rows,
                 actual_protocol_exchanges=sum(len(values) for row in rows for values in row.get('peer_reports', [])),
                 clock_acceptance=False, full_F12_complete=False)
    (args.directory / 'acceptance.json').write_text(json.dumps(proof, indent=2) + '\n')
    raise SystemExit(0 if proof['passed'] else 1)


if __name__ == '__main__':
    main()
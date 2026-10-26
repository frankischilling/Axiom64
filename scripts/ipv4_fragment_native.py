# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the actual fragment client on Linux through private TAP Ethernet peers."""
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
from fetch import ROOT
from ipv4_fragments import FragmentPeer
from ipv4_expiry_capture import verify_capture
from ipv4_path_mtu_capture import verify_capture as verify_path_mtu
from ipv4_path_mtu_lifetime_capture import verify_capture as verify_path_lifetime
from ipv4_query_model import query_model
from tcp_fault_native import Capture
from native_ipv4_state import NativeIpv4State
from native_icmp_preflight import NativeIcmpPreflight
from native_icmp_preflight_capture import verify_capture as verify_preflight


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def client(profile, pmtu_only=False, lifetime_only=False):
    binary = ROOT / 'build' / {'native': 'ipv4-native', 'static': 'ipv4-tests',
                              'dynamic': 'ipv4-dynamic'}[profile]
    mode = '--path-mtu-lifetime' if lifetime_only else '--path-mtu' if pmtu_only else '--fragments'
    command = [str(binary), mode]
    if profile == 'dynamic':
        command.insert(0, str(loader('build')))
    return command


def send_packets(taps, captures, peers, lane, packets):
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    mac = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
    for packet, broadcast in packets:
        frame = ((b'\xff' * 6 if broadcast else guest) + mac + b'\x08\0' + packet).ljust(60, b'\0')
        context = next((item for item in peers[lane].expiry.contexts
                        if item['packet_hex'] == packet.hex() and 'capture_monotonic' not in item), None)
        if context is not None:
            # A reader delayed by the preceding fragment burst can observe less
            # than eight seconds between packets sent eight seconds apart.
            # Start the next gap after this independent receipt instead.
            observed = captures[lane].observe_injection(frame, lambda data: os.write(taps[lane], data))
            if observed < context['monotonic']:
                raise ValueError('context capture precedes its actual injection')
            context['capture_monotonic'] = observed
        elif os.write(taps[lane], frame) != len(frame):
            raise OSError('short TAP fragment injection')


def child(profile, directory, pmtu_only=False, lifetime_only=False):
    directory.mkdir(exist_ok=False)
    peers = [FragmentPeer(lane, native=True) for lane in range(2)]
    taps, captures, statistics, links = [], [], [], []
    state = None
    state_errors, observed_events, observed_deadlines = [], [0, 0], set()
    capture_finalization = []

    def observe(reason):
        if state is None:
            return
        try:
            state.snapshot(reason)
        except Exception as exception:
            state_errors.append(f'{reason}: {type(exception).__name__}: {exception}')

    def observe_expiry(lane):
        expiry = peers[lane].expiry
        for position in range(observed_events[lane], len(expiry.events)):
            observe(f'expiry lane {lane}: {expiry.events[position]["name"]}')
        observed_events[lane] = len(expiry.events)
        if expiry.start is not None and not expiry.acknowledged:
            for seconds in (59, 66, 100):
                key = lane, seconds
                if key not in observed_deadlines and time.monotonic() - expiry.start >= seconds:
                    observed_deadlines.add(key)
                    observe(f'expiry lane {lane}: elapsed {seconds} seconds')
    process = None
    error = None
    command = client(profile, pmtu_only, lifetime_only)
    preflight = NativeIcmpPreflight(directory) if not pmtu_only and not lifetime_only else None
    model = query_model(platform.uname()._asdict())
    sources = ['userspace/tests/net/ipv4.c', 'userspace/tests/net/ipv4_fragments.c',
               'userspace/tests/net/ipv4_aliases.c', 'userspace/tests/net/ipv4_aliases.h',
               'scripts/compile_uapi_client.py', 'scripts/linux_uapi.py',
               'scripts/build_openssl.py', 'ports.lock.json',
               'userspace/tests/net/ipv4_path_mtu.c', 'userspace/tests/net/ipv4_path_mtu.h',
               'scripts/ipv4_path_mtu.py',
               'scripts/ipv4_path_mtu_capture.py',
               'scripts/ipv4_query_model.py', 'userspace/tests/net/ipv4_query.h',
               'scripts/ipv4_path_mtu_lifetime.py', 'scripts/ipv4_path_mtu_lifetime_capture.py',
               'userspace/tests/net/ipv4_fragments.h', 'scripts/ipv4_fragments.py',
               'scripts/ipv4_fragment_native.py', 'scripts/ipv4_expiry_capture.py',
               'scripts/tcp_fault_native.py', 'scripts/native_ipv4_state.py',
               'scripts/native_icmp_preflight.py', 'scripts/native_icmp_preflight_capture.py', 'Makefile']
    before = dict(profile=profile, pmtu_only=pmtu_only, lifetime_only=lifetime_only, query_model=model,
                  kernel=platform.uname()._asdict(), command=command,
                  source_sha256={name: digest(ROOT / name) for name in sources},
                  executable_sha256={name: digest(Path(name)) for name in command[:-1]},
                  requested_fragment_timeout_seconds=60,
                  requested_path_mtu_lifetime_seconds=600,
                  native_icmp_error_tos=0xc0,
                  expiry_quote_upper_seconds=peers[0].expiry.latest_quote_seconds,
                  expiry_context_gap_seconds=peers[0].expiry.context_gap_seconds,
                  expiry_quiet_delay_seconds=peers[0].expiry.quiet_delay_seconds,
                  namespace_linkage='private network namespace; two private TAP devices',
                  read_only_kernel_state='native-kernel-state.jsonl')
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

    def deliver(lane, packet, expiry):
        if expiry:
            send_packets(taps, captures, peers, lane, peers[lane].expiry.receive(packet))
            observe_expiry(lane)
        else:
            send_packets(taps, captures, peers, lane,
                         [(payload, False) for payload in peers[lane].receive(packet)])

    fragment_timeout = None
    try:
        state = NativeIpv4State(directory)
        observe('before namespace configuration')
        # Match the unchanged guest policy in this private network namespace only.
        subprocess.run(['sysctl', '-w', 'net.ipv4.ipfrag_time=60'], check=True)
        fragment_timeout = int(Path('/proc/sys/net/ipv4/ipfrag_time').read_text())
        if fragment_timeout != 60:
            raise ValueError('native fragment lifetime differs from the 60-second guest policy')
        if int(Path('/proc/sys/net/ipv4/route/mtu_expires').read_text()) != 600:
            raise ValueError('native path lifetime differs from the unchanged ten-minute policy')
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
        observe('interfaces ready before client execution')
        with (directory / 'client.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL, cwd=ROOT)
            while True:
                bound = 120 if pmtu_only else 640 if lifetime_only else 780
                if time.monotonic() - started > bound:
                    raise TimeoutError(f'IPv4 comparison exceeded its {bound}-second bound')
                if process.poll() not in (None, 0):
                    raise RuntimeError(f'fragment client exited {process.returncode}')
                if preflight is not None:
                    preflight.tick()
                for lane, peer in enumerate(peers):
                    send_packets(taps, captures, peers, lane, peer.expiry.tick())
                    observe_expiry(lane)
                for key, _ in selector.select(.02):
                    lane = key.data
                    frame = os.read(key.fd, 65535)
                    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
                    mac = bytes([2, 0x41, 0x58, 0x49, 0x50, lane])
                    local = bytes([10, 23, lane + 1, 2])
                    remote = bytes([10, 23, lane + 1, 1])
                    path_arp = peers[lane].path_mtu.arp_reply(frame)
                    if path_arp is not None:
                        if os.write(key.fd, path_arp) != len(path_arp):
                            raise OSError('short path-MTU ARP injection')
                        continue
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
                        if preflight is not None and preflight.receive(lane, frame):
                            observe('native ICMP preflight completed before original fragment input')
                            for held_lane, held_frame in preflight.release():
                                held_packet = held_frame[14:14+int.from_bytes(held_frame[16:18], 'big')]
                                deliver(held_lane, held_packet, peers[held_lane].expiry.accepts(held_packet))
                            continue
                        packet = frame[14:]
                        total = int.from_bytes(packet[2:4], 'big')
                        packet = packet[:total]
                        expiry = peers[lane].expiry.accepts(packet)
                        if not expiry and not peers[lane].accepts(packet):
                            continue
                        if frame[:12] != mac + guest:
                            raise ValueError('native fragment control Ethernet ownership differs')
                        if total > len(packet):
                            raise ValueError('truncated native control packet')
                        if preflight is not None and not preflight.passed:
                            preflight.hold(lane, frame, taps, captures)
                        else:
                            deliver(lane, packet, expiry)
                if process.poll() == 0 and all(
                    (lifetime_only or peer.path_mtu.passed) and
                    (pmtu_only or peer.path_mtu.lifetime.passed) and
                    (pmtu_only or lifetime_only or
                     (peer.acknowledged and peer.output.acknowledged and peer.expiry.passed))
                    for peer in peers):
                    break
    except Exception as exception:
        error = f'{type(exception).__name__}: {exception}'
    finally:
        observe('before client and capture shutdown')
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for lane, capture in enumerate(captures):
            try:
                stats = capture.close()
                statistics.append(stats)
                capture_finalization.append(dict(lane=lane, statistics=stats, error=None))
            except Exception as exception:
                capture_finalization.append(dict(lane=lane, statistics=None,
                    error=f'{type(exception).__name__}: {exception}'))
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
        observe('after capture and interface statistics')
        state_report = dict(path='native-kernel-state.jsonl', complete=False, diagnostic_only=True)
        if state is not None:
            try:
                state_report = state.close()
            except Exception as exception:
                state_errors.append(f'close: {type(exception).__name__}: {exception}')
        if state_errors or not state_report['complete']:
            error = error or 'native kernel-state evidence is incomplete'
    text = (directory / 'client.log').read_text(errors='replace') if process else ''
    completed = [peer.completed for peer in peers]
    acknowledged = [peer.acknowledged for peer in peers]
    output_cases = [peer.output.completed for peer in peers]
    output_ack = [peer.output.acknowledged for peer in peers]
    markers = lifetime_only or all(f'IPV4_PATH_MTU_PASS index={lane + 1} cases=18 policies_each=6\n' in text
                                  for lane in range(2))
    if not pmtu_only:
        markers = markers and all(f'IPV4_PATH_MTU_LIFETIME_PASS index={lane + 1} ' in text
                                  for lane in range(2))
    if not pmtu_only and not lifetime_only:
        markers = markers and all(f'IPV4_FRAGMENT_PASS index={lane + 1} cases=6\n' in text for lane in range(2))
        markers = markers and all(f'IPV4_FRAGMENT_OUTPUT_PASS index={lane + 1} cases=21\n' in text
                                  for lane in range(2))
        markers = markers and all(f'IPV4_FRAGMENT_EXPIRY_PASS index={lane + 1} ' in text for lane in range(2))
    expiry_audits = []
    preflight_audit = None
    if not pmtu_only and not lifetime_only and error is None and process is not None and process.returncode == 0 and markers:
        try:
            preflight_audit = verify_preflight(directory, statistics,
                damage_archive=directory/'native-icmp-preflight-damaged.zip')
            for lane in range(2):
                expiry_audits.append(verify_capture(directory / f'lane{lane}.pcap', lane,
                    directory / 'client.log', native=True,
                    damage_archive=directory / f'lane{lane}-expiry-damaged.zip'))
        except Exception as exception:
            error = f'expiry capture audit: {exception}'
    path_audits = []
    if not lifetime_only and error is None and process is not None and process.returncode == 0 and markers:
        try:
            for lane in range(2):
                path_audits.append(verify_path_mtu(directory / f'lane{lane}.pcap', lane,
                    directory / 'client.log', native=True, query_model=model,
                    damage_archive=directory / f'lane{lane}-pmtu-damaged.zip'))
        except Exception as exception:
            error = f'path MTU capture audit: {exception}'
    lifetime_audits = []
    if not pmtu_only and error is None and process is not None and process.returncode == 0 and markers:
        try:
            for lane in range(2):
                lifetime_audits.append(verify_path_lifetime(directory / f'lane{lane}.pcap', lane,
                    directory / 'client.log', native=True,
                    damage_archive=directory / f'lane{lane}-pmtu-lifetime-damaged.zip'))
        except Exception as exception:
            error = f'path MTU lifetime capture audit: {exception}'
    result = dict(profile=profile, pmtu_only=pmtu_only, lifetime_only=lifetime_only,
                  error=error, returncode=process.returncode if process else None,
                  cases=completed, final_ack=acknowledged, frames=[peer.frames for peer in peers],
                  output_cases=output_cases, output_final_ack=output_ack,
                  output_frames=[peer.output.frames for peer in peers],
                  fragment_expiry=[peer.expiry.report() for peer in peers],
                  native_fragment_timeout_seconds=fragment_timeout,
                  fragment_expiry_capture_audits=expiry_audits,
                  native_icmp_preflight_capture_audit=preflight_audit,
                  path_mtu=[peer.path_mtu.report() for peer in peers],
                  path_mtu_capture_audits=path_audits,
                  path_mtu_lifetime=[peer.path_mtu.lifetime.report() for peer in peers],
                  path_mtu_lifetime_capture_audits=lifetime_audits,
                  link_statistics=links,
                  seconds=time.monotonic() - started, capture_statistics=statistics,
                  native_kernel_state=state_report, native_kernel_state_errors=state_errors,
                  capture_finalization=capture_finalization,
                  source_sha256=before['source_sha256'],
                  passed=(error is None and process is not None and process.returncode == 0 and
                          (lifetime_only or all(peer.path_mtu.passed for peer in peers)) and
                          (pmtu_only or all(peer.path_mtu.lifetime.passed for peer in peers)) and
                          (pmtu_only or lifetime_only or (completed == [6, 6] and all(acknowledged) and output_cases == [21, 21] and
                          all(output_ack) and all(peer.expiry.passed for peer in peers) and
                          preflight.passed and preflight_audit is not None)) and
                          markers and len(statistics) == 2 and
                          len(path_audits) == (0 if lifetime_only else 2) and
                          len(lifetime_audits) == (0 if pmtu_only else 2) and
                          len(expiry_audits) == (0 if pmtu_only or lifetime_only else 2)))
    (directory / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    return result['passed']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/ipv4-fragments-native')
    parser.add_argument('--child', choices=['native', 'static', 'dynamic'])
    focused = parser.add_mutually_exclusive_group()
    focused.add_argument('--pmtu-only', action='store_true',
                         help='focused PMTU policies; excludes fragment and ten-minute expiry acceptance')
    focused.add_argument('--lifetime-only', action='store_true',
                         help='complete ten-minute PMTU lifetime; excludes fragment and six-policy acceptance')
    args = parser.parse_args()
    directory = args.directory.resolve()
    if directory == (ROOT / 'build').resolve() or not directory.is_relative_to((ROOT / 'build').resolve()):
        raise ValueError('native evidence must have a dedicated directory beneath build/')
    if args.child:
        return 0 if child(args.child, directory, args.pmtu_only, args.lifetime_only) else 1
    directory.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    with (directory / 'build.log').open('wb') as log:
        built = subprocess.run(['make', '-j2', 'build/ipv4-native', 'build/ipv4-tests',
                                'build/ipv4-dynamic'], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    results = []
    if built.returncode == 0:
        def compare(profile):
            command = ['unshare', '--net', sys.executable, __file__, '--child', profile,
                       '--directory', str(directory / profile)]
            if args.pmtu_only:
                command.append('--pmtu-only')
            if args.lifetime_only:
                command.append('--lifetime-only')
            completed = subprocess.run(command, cwd=ROOT)
            return dict(profile=profile, returncode=completed.returncode)

        # Programs and loaders are immutable after the shared build. Each child
        # owns its namespace, TAPs, captures and output directory while time elapses.
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(compare, ['native', 'static', 'dynamic']))
    passed = built.returncode == 0 and len(results) == 3 and all(row['returncode'] == 0 for row in results)
    (directory / 'receipt.json').write_text(json.dumps(dict(passed=passed, pmtu_only=args.pmtu_only,
        lifetime_only=args.lifetime_only,
        build_returncode=built.returncode, profiles=results, seconds=time.monotonic() - started,
        execution='three private network namespaces after one shared build'), indent=2) + '\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())

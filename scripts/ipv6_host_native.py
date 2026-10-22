# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare the actual IPv6 control client on isolated native Ethernet links."""
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
import socket
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
from ipv6_copy_model import parse_probe
from ipv6_send_model import parse_probe as parse_send_probe


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def child(profile, directory, suite='host', parent_namespace=None):
    namespace = Path('/proc/self/ns/net').stat().st_ino
    if parent_namespace is None or namespace == parent_namespace:
        raise ValueError('native network fixture requires its own network namespace')
    directory.mkdir(exist_ok=False)
    program = ROOT / 'build' / ('ipv6-' + suite + '-' + profile)
    command = [str(program)]
    if profile == 'dynamic':
        command.insert(0, str(loader('build')))
    sources = {name: digest(ROOT / name) for name in (
        'userspace/tests/net/ipv6_' + suite + '.c', 'scripts/ipv6_host_native.py',
        'scripts/ipv6_host_peer.py', 'scripts/ipv6_host_capture.py',
        'scripts/ipv6_sockets_peer.py', 'scripts/ipv6_sockets_capture.py',
        'scripts/ipv6_fragments_peer.py', 'scripts/ipv6_fragments_capture.py', 'scripts/tcp_fault_native.py')}
    for name in ('scripts/ipv6_output_peer.py', 'scripts/ipv6_output_capture.py',
                 'scripts/ipv6_pmtu_peer.py', 'scripts/ipv6_pmtu_capture.py',
                 'scripts/ipv6_errors_peer.py', 'scripts/ipv6_errors_capture.py',
                 'scripts/ipv6_expiry_peer.py', 'scripts/ipv6_expiry_capture.py',
                 'scripts/ipv6_controls_peer.py', 'scripts/ipv6_controls_capture.py',
                 'userspace/tests/net/ipv6_fixture.h'):
        sources[name] = digest(ROOT / name)
    products = {name: digest(Path(name)) for name in command}
    if suite == 'controls':
        for name in ('Makefile', 'userspace/tests/net/ipv6_control.c',
                     'userspace/tests/net/ipv6_control_faults.c',
                     'userspace/tests/net/ipv6_control_header_faults.c',
                     'scripts/ipv6_control_contract.py', 'scripts/ipv6_control_fault_contract.py',
                     'scripts/ipv6_control_header_contract.py', 'scripts/ipv6_controls_contract_test.py'):
            sources[name] = digest(ROOT / name)
    saved = directory / 'products'
    if suite == 'output':
        for name in ('Makefile', 'userspace/tests/net/ipv6_send_controls.c',
                     'userspace/tests/net/ipv6_send_controls_wire.c', 'scripts/ipv6_send_controls_peer.py',
                     'scripts/ipv6_send_controls_capture.py',
                 'scripts/ipv6_extension_peer.py', 'scripts/ipv6_extension_capture.py',
                 'userspace/tests/net/ipv6_extension_wire.c',
                 'scripts/ipv6_routing_peer.py', 'scripts/ipv6_routing_capture.py',
                 'userspace/tests/net/ipv6_routing_wire.c', 'userspace/tests/net/ipv6_extension_controls.c',
                 'scripts/ipv6_extension_contract.py', 'scripts/ipv6_extension_execution.py',
                 'scripts/tests/fixtures/ipv6-extension-controls-linux7.json',
                 'scripts/ipv6_sticky_peer.py', 'scripts/ipv6_sticky_capture.py',
                 'userspace/tests/net/ipv6_sticky_wire.c', 'userspace/tests/net/ipv6_sticky_controls.c',
                 'scripts/ipv6_sticky_contract.py', 'scripts/tests/fixtures/ipv6-sticky-controls-linux7.json',
                     'scripts/ipv6_send_controls_contract.py', 'scripts/ipv6_send_controls_test.py'):
            sources[name] = digest(ROOT / name)
    if suite == 'cached':
        for name in ('Makefile', 'scripts/ipv6_cached_peer.py', 'scripts/ipv6_cached_capture.py',
                     'scripts/packet_observation.py', 'scripts/tcp_capture_clock.py',
                     'scripts/ipv4_expiry_capture.py', 'scripts/ipv6_controls_capture.py'):
            sources[name] = digest(ROOT / name)
    if suite == 'errors':
        for name in ('Makefile', 'userspace/tests/net/ipv6_error_controls.c',
                     'userspace/tests/net/ipv6_error_metadata.c',
                     'scripts/ipv6_extension_execution.py',
                     'userspace/tests/net/ipv6_receive_extensions.c',
                     'scripts/ipv6_receive_extensions_contract.py',
                     'scripts/tests/fixtures/ipv6-receive-extensions-linux7.json',
                     'scripts/ipv6_error_metadata_peer.py', 'scripts/ipv6_error_metadata_capture.py',
                     'scripts/ipv6_error_controls_contract.py', 'scripts/ipv6_error_controls_test.py'):
            sources[name] = digest(ROOT / name)
    model_program = ROOT / 'build/ipv6-copy-model-native' if suite in ('controls', 'errors') else None
    if model_program:
        sources['userspace/tests/net/ipv6_copy_model.c'] = digest(ROOT / 'userspace/tests/net/ipv6_copy_model.c')
        sources['scripts/ipv6_copy_model.py'] = digest(ROOT / 'scripts/ipv6_copy_model.py')
        products[str(model_program)] = digest(model_program)
    send_model_program = ROOT / 'build/ipv6-send-model-native' if suite == 'output' else None
    if send_model_program:
        for name in ('userspace/tests/net/ipv6_send_model.c', 'scripts/ipv6_send_model.py'):
            sources[name] = digest(ROOT / name)
        products[str(send_model_program)] = digest(send_model_program)
    saved.mkdir()
    if send_model_program:
        shutil.copy2(send_model_program, saved / 'send-model-native')
        shutil.copy2(ROOT / 'userspace/tests/net/ipv6_send_model.c', saved / 'send-model.c')
    if model_program:
        shutil.copy2(model_program, saved / 'copy-model-native')
        shutil.copy2(ROOT / 'userspace/tests/net/ipv6_copy_model.c', saved / 'copy-model.c')
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
    if suite in ('errors', 'output'):
        for name in ('all', 'default', 'lo'):
            settings[f'net.ipv6.conf.{name}.seg6_enabled'] = 1
    if suite in ('fragments', 'expiry'):
        settings['net.ipv6.conf.default.router_solicitations'] = 0
        timer = 'net.ipv6.ip6frag_time' if suite == 'fragments' else 'net.ipv6.route.mtu_expires'
        lifetime = subprocess.check_output(['sysctl', '-n', timer], text=True).strip()
        wanted = '60' if suite == 'fragments' else '600'
        if lifetime != wanted:
            raise ValueError(f'native {timer} must remain its real {wanted}-second default')
        settings[timer] = int(lifetime)
    for name, value in settings.items():
        subprocess.run(['sysctl', '-q', '-w', f'{name}={value}'], check=True)
    (directory / 'preexecution.json').write_text(json.dumps(dict(profile=profile,
        kernel=platform.uname()._asdict(), command=command, settings=settings,
        network_namespace=namespace, parent_network_namespace=parent_namespace,
        source_sha256=sources, product_sha256=products), indent=2) + '\n')
    peer_type = Peer
    if suite == 'sockets':
        from ipv6_sockets_peer import Peer as SocketPeer
        peer_type = SocketPeer
    elif suite == 'fragments':
        from ipv6_fragments_peer import Peer as FragmentPeer
        peer_type = FragmentPeer
    elif suite == 'output':
        from ipv6_output_peer import Peer as OutputPeer
        peer_type = OutputPeer
    elif suite == 'pmtu':
        from ipv6_pmtu_peer import Peer as PmtuPeer
        peer_type = PmtuPeer
    elif suite == 'errors':
        from ipv6_errors_peer import Peer as ErrorPeer
        peer_type = ErrorPeer
    elif suite == 'expiry':
        from ipv6_expiry_peer import Peer as ExpiryPeer
        peer_type = ExpiryPeer
    elif suite == 'cached':
        from ipv6_cached_peer import Peer as CachedPeer
        peer_type = CachedPeer
    elif suite == 'controls':
        from ipv6_controls_peer import Peer as ControlsPeer
        peer_type = ControlsPeer
    peers = [peer_type(lane, native=True) for lane in range(2)]
    taps, captures, statistics, interfaces = [], [], [], []
    selector = selectors.DefaultSelector()
    process, error = None, None
    began = time.monotonic()
    try:
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        if send_model_program:
            observed = subprocess.run([str(send_model_program)], stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT)
            (directory / 'native-send-model.log').write_bytes(observed.stdout)
            observed.check_returncode()
            kernel = json.loads((directory / 'preexecution.json').read_text())['kernel']
            send_model = parse_send_probe(observed.stdout.decode(), kernel['release'])
            for peer in peers:
                peer.set_send_model(send_model)
            model = dict(kernel=kernel, **send_model,
                         probe_log_sha256=hashlib.sha256(observed.stdout).hexdigest(),
                         probe_program=str(send_model_program),
                         probe_program_sha256=products[str(send_model_program)],
                         probe_source_sha256=sources['userspace/tests/net/ipv6_send_model.c'])
            (directory / 'native-send-model.json').write_text(json.dumps(model, indent=2) + '\n')
        if model_program:
            observed = subprocess.run([str(model_program)], stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, check=True)
            (directory / 'native-copy-model.log').write_bytes(observed.stdout)
            kernel = json.loads((directory / 'preexecution.json').read_text())['kernel']
            copy_order = parse_probe(observed.stdout.decode(), kernel['release'])
            model = dict(kernel=kernel, source_order=copy_order,
                         probe_log_sha256=hashlib.sha256(observed.stdout).hexdigest(),
                         probe_program=str(model_program), probe_program_sha256=products[str(model_program)],
                         probe_source_sha256=sources['userspace/tests/net/ipv6_copy_model.c'])
            (directory / 'native-copy-model.json').write_text(json.dumps(model, indent=2) + '\n')
        for lane in range(2):
            tap = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
            taps.append(tap)
            name = f'eth{lane}'
            fcntl.ioctl(tap, 0x400454ca, struct.pack('16sH', name.encode(), 0x1002))
            subprocess.run(['ip', 'link', 'set', 'dev', name, 'address',
                            peers[lane].guest.hex(':'), 'mtu', '1500', 'up'], check=True)
            interfaces.append(dict(lane=lane, name=name, index=socket.if_nametoindex(name)))
            selector.register(tap, selectors.EVENT_READ, lane)
            captures.append(Capture(name, directory / f'lane{lane}.pcap'))
            if suite in ('pmtu', 'errors', 'cached'):
                peers[lane].observe_input = captures[-1].watch
        (directory / 'interfaces.json').write_text(json.dumps(interfaces, indent=2) + '\n')
        with (directory / 'client.log').open('wb') as output:
            process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT)
            while process.poll() is None:
                if time.monotonic() - began > (650 if suite == 'expiry' else 160 if suite == 'fragments' else 120 if suite in ('output', 'pmtu', 'errors') else 45):
                    raise TimeoutError('native IPv6 client exceeded its overall deadline')
                for key, _ in selector.select(.02):
                    peers[key.data].receive(os.read(key.fd, 65535))
                for lane, peer in enumerate(peers):
                    tick = getattr(peer, 'tick', None)
                    if tick:
                        tick()
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
                checker = verify_capture
                if suite == 'sockets':
                    from ipv6_sockets_capture import verify_capture as checker
                elif suite == 'fragments':
                    from ipv6_fragments_capture import verify_capture as checker
                elif suite == 'output':
                    from ipv6_output_capture import verify_capture as checker
                elif suite == 'pmtu':
                    from ipv6_pmtu_capture import verify_capture as checker
                elif suite == 'errors':
                    from ipv6_errors_capture import verify_capture as checker
                elif suite == 'expiry':
                    from ipv6_expiry_capture import verify_capture as checker
                elif suite == 'cached':
                    from ipv6_cached_capture import verify_capture as checker
                elif suite == 'controls':
                    from ipv6_controls_capture import verify_capture as checker
                extra = dict(statistics=statistics[lane], interface_index=interfaces[lane]['index']) if suite in ('fragments', 'output', 'pmtu', 'errors', 'expiry', 'controls', 'cached') else {}
                if model_program:
                    extra['native_copy_order'] = copy_order
                if send_model_program:
                    extra['native_send_class'] = send_model['minus_one_class']
                audits.append(checker(directory / f'lane{lane}.pcap', lane,
                    directory / 'client.log', directory / f'lane{lane}-damaged.zip', native=True, **extra))
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
                  interfaces=interfaces, interface_record_sha256=(digest(directory / 'interfaces.json')
                      if (directory / 'interfaces.json').is_file() else None),
                  native_copy_model_sha256=(digest(directory / 'native-copy-model.json')
                      if (directory / 'native-copy-model.json').is_file() else None),
                  native_send_model_sha256=(digest(directory / 'native-send-model.json')
                      if (directory / 'native-send-model.json').is_file() else None),
                  settings=settings, full_F12_complete=False)
    (directory / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ('peers', 'settings')}), flush=True)
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--suite', choices=('host', 'sockets', 'fragments', 'output', 'pmtu', 'errors', 'expiry', 'controls', 'cached'), default='host')
    parser.add_argument('--workers', type=int, choices=(1, 2, 3), default=1)
    parser.add_argument('--child', choices=('native', 'static', 'dynamic'))
    parser.add_argument('--parent-network-namespace', type=int)
    parser.add_argument('--profile', choices=('native', 'static', 'dynamic', 'all'), default='all')
    parser.add_argument('--output-directory', type=Path, default=None)
    args = parser.parse_args()
    args.output_directory = args.output_directory or ROOT / 'build' / ('ipv6-' + args.suite + '-native-wire')
    if args.child:
        return child(args.child, args.output_directory, args.suite, args.parent_network_namespace)
    profiles = ('native', 'static', 'dynamic') if args.profile == 'all' else (args.profile,)
    targets = ['build/ipv6-' + args.suite + '-' + profile for profile in profiles]
    if args.suite in ('controls', 'errors'):
        targets.append('build/ipv6-copy-model-native')
    if args.suite == 'output':
        targets.append('build/ipv6-send-model-native')
    subprocess.run(['make', '-j2', *targets], cwd=ROOT, check=True)
    args.output_directory.mkdir(parents=True, exist_ok=True)
    def run(profile):
        directory = args.output_directory / profile
        result = subprocess.run(['unshare', '--net', sys.executable, '-B', 'scripts/ipv6_host_native.py',
                                 '--child', profile, '--suite', args.suite, '--output-directory', str(directory),
                                 '--parent-network-namespace', str(Path('/proc/self/ns/net').stat().st_ino)], cwd=ROOT)
        return dict(profile=profile, returncode=result.returncode)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(run, profiles))
    (args.output_directory / 'receipt.json').write_text(json.dumps(results, indent=2) + '\n')
    return 0 if all(not row['returncode'] for row in results) else 1


if __name__ == '__main__':
    sys.exit(main())

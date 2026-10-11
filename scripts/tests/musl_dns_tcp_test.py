#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise actual libc TCP framing and query ownership in private namespaces."""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
CASES = ('valid', 'large', 'split', 'wrong-id', 'wrong-id-valid', 'wrong-name',
         'wrong-type', 'wrong-class', 'query-bit', 'opcode', 'short-prefix',
         'short-body', 'short-frame', 'refused', 'silent', 'questionless-negative',
         'casefold', 'compression-loop', 'oversized-valid', 'oversized-wrong-id-valid',
         'udp-wrong-question-valid')
GOOD = {'valid': 1, 'large': 40, 'split': 40, 'wrong-id-valid': 1, 'casefold': 1,
        'oversized-valid': 40, 'oversized-wrong-id-valid': 1, 'udp-wrong-question-valid': 1}


def exact(channel, size):
    data = bytearray()
    while len(data) < size:
        part = channel.recv(size - len(data))
        if not part:
            raise AssertionError('EOF before the complete TCP query')
        data.extend(part)
    return bytes(data)


def answer(query, case):
    ident = int.from_bytes(query[:2], 'big') ^ int(case in ('wrong-id', 'wrong-id-valid', 'oversized-wrong-id-valid'))
    flags = 0x8180
    if case == 'query-bit':
        flags &= ~0x8000
    if case == 'opcode':
        flags |= 0x0800
    if case == 'refused':
        flags |= 5
    question = bytearray(query[12:])
    if case == 'wrong-name':
        question[1] ^= 1
    if case == 'wrong-type':
        question[-3] = 28
    if case == 'wrong-class':
        question[-1] = 3
    if case == 'casefold':
        question = bytearray(bytes(question).upper())
    if case == 'compression-loop':
        question = bytearray(b'\xc0\x0c\0\1\0\1')
    if case == 'questionless-negative':
        return struct.pack('!6H', ident, 0x8183, 0, 0, 0, 0)
    count = 40 if case in ('large', 'split', 'oversized-valid') else 1
    poisoned = case not in ('valid', 'large', 'split', 'casefold', 'oversized-valid', 'udp-wrong-question-valid')
    records = b''.join(b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) +
                       (0x0a17ff01 + i if poisoned else 0x0a174001 + i).to_bytes(4, 'big')
                       for i in range(count))
    result = struct.pack('!HHHHHH', ident, flags, 1, count, 0, 0) + question + records
    if case.startswith('oversized'):
        # Padding is outside the declared RR sections. The pinned lookup API
        # keeps its 768-byte parse limit, but the transport must drain this
        # entire frame before accepting it or reading the next frame.
        result += bytes(4096 - len(result))
    return result


def lookup(binary, loader, case, comparison=False):
    events, failures = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
        udp.bind(('127.0.0.53', 53))
        udp.settimeout(3)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(('127.0.0.53', 53))
        tcp.listen()
        tcp.settimeout(3)

        def send(channel, payload):
            channel.sendall(payload)
            events.append(dict(kind='tcp-send', bytes=payload.hex(),
                               monotonic_ns=time.monotonic_ns()))

        def peer():
            try:
                query, sender = udp.recvfrom(4096)
                assert query[4:6] == b'\0\1' and query[-4:] == b'\0\1\0\1'
                events.append(dict(kind='udp-query', bytes=query.hex(), sender=list(sender)))
                tc = query[:2] + struct.pack('!HHHHH', 0x8380, 1, 0, 0, 0) + query[12:]
                if case == 'udp-wrong-question-valid':
                    wrong = bytearray(tc)
                    wrong[13] ^= 1
                    udp.sendto(wrong, sender)
                    events.append(dict(kind='udp-unowned-tc', bytes=wrong.hex(), monotonic_ns=time.monotonic_ns()))
                    tcp.settimeout(.12)
                    try:
                        premature, _ = tcp.accept()
                    except socket.timeout:
                        pass
                    else:
                        premature.close()
                        raise AssertionError('unowned UDP TC must not start TCP')
                    tcp.settimeout(3)
                udp.sendto(tc, sender)
                events.append(dict(kind='udp-tc', bytes=tc.hex()))
                channel, sender = tcp.accept()
                with channel:
                    channel.settimeout(3)
                    channel.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    prefix = exact(channel, 2)
                    body = exact(channel, int.from_bytes(prefix, 'big'))
                    assert body == query, 'fallback must preserve the selected query'
                    events.append(dict(kind='tcp-query', bytes=(prefix + body).hex(),
                                       sender=list(sender)))
                    reply = answer(query, case)
                    framed = len(reply).to_bytes(2, 'big') + reply
                    if case == 'silent':
                        # The client must expire while the peer remains open.
                        time.sleep(6 if comparison else 1.5)
                    elif case == 'short-prefix':
                        send(channel, framed[:1])
                    elif case == 'short-body':
                        send(channel, framed[:15])
                    elif case == 'short-frame':
                        send(channel, b'\0\x0c' + reply[:12])
                    elif case in ('wrong-id-valid', 'oversized-wrong-id-valid'):
                        valid = answer(query, 'valid')
                        send(channel, framed + len(valid).to_bytes(2, 'big') + valid)
                    elif case == 'split':
                        for chunk in (framed[:1], framed[1:2], framed[2:19],
                                      framed[19:401], framed[401:]):
                            send(channel, chunk)
                            time.sleep(.025)
                    else:
                        send(channel, framed)
            except Exception as error:
                failures.append(repr(error))

        thread = threading.Thread(target=peer)
        thread.start()
        command = [str(binary), 'x.fixture.']
        if loader:
            command.insert(0, str(loader))
        started = time.monotonic_ns()
        process = None
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=4)
        except subprocess.TimeoutExpired:
            if not comparison:
                raise
        finally:
            thread.join(8)
        assert not thread.is_alive() and not failures, failures
        if process is None:
            return dict(case=case, passed=False, completed=False, harness_timeout_ms=4000,
                        error=None, count=None, bad=None, elapsed_ms=None,
                        host_elapsed_ms=(time.monotonic_ns() - started) / 1e6, events=events)
        assert process.returncode == 0, process.stdout + process.stderr
    found = re.fullmatch(r'DNS_TCP_PROBE name=x.fixture\. error=(-?\d+) count=(\d+) '
                         r'bad=(\d+) elapsed_ms=([\d.]+)\n', process.stdout)
    assert found, process.stdout + process.stderr
    error, count, bad = map(int, found.group(1, 2, 3))
    elapsed = float(found[4])
    expected = GOOD.get(case, 0)
    passed = count == expected and bad == 0 and ((error == 0) == bool(expected))
    if not expected:
        passed &= error == (-2 if case == 'questionless-negative' else -3)
    if case == 'silent':
        passed &= 850 <= elapsed <= 1400
    if case == 'questionless-negative':
        passed &= error == -2
    return dict(case=case, passed=bool(passed), completed=True, error=error, count=count, bad=bad,
                elapsed_ms=elapsed, host_elapsed_ms=(time.monotonic_ns() - started) / 1e6,
                output=process.stdout, events=events)


def namespace(out, providers, cases):
    parent = json.loads((out / 'namespaces.json').read_text())
    actual = {kind: os.readlink('/proc/self/ns/' + kind) for kind in ('mnt', 'net')}
    assert all(actual[kind] != parent[kind] for kind in actual)
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    for name in ('hosts', 'resolv.conf'):
        subprocess.run(['mount', '--bind', str(out / name), '/etc/' + name], check=True)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    records = []
    for provider in providers:
        binary, loader = providers[provider]
        for case in cases:
            record = lookup(binary, loader, case, comparison=provider == 'glibc')
            record['provider'] = provider
            records.append(record)
            (out / 'partial-results.json').write_text(json.dumps(records, indent=2) + '\n')
            print(f"DNS_TCP_SOCKET provider={provider} case={case} passed={record['passed']} "
                  f"error={record['error']} count={record['count']} bad={record['bad']}", flush=True)
    # Native glibc is a measured comparison. Its differing retry/EOF behavior
    # is retained; the musl transport contract must pass every case.
    common = ('valid', 'large', 'split', 'casefold', 'oversized-valid')
    evidence = dict(passed=all(row['passed'] for row in records if row['provider'] != 'glibc' or
                              row['case'] in common), records=records,
                    parent_namespaces=parent, fixture_namespaces=actual)
    (out / 'results.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return 0 if evidence['passed'] else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--static-compiler', default='musl-gcc')
    parser.add_argument('--dynamic-compiler', default='musl-gcc')
    parser.add_argument('--loader', type=Path, default=Path('/lib/ld-musl-x86_64.so.1'))
    parser.add_argument('--runtime-loader', type=Path)
    parser.add_argument('--patched', action='store_true')
    parser.add_argument('--compare-glibc', action='store_true')
    parser.add_argument('--cases', nargs='+', choices=CASES, default=list(CASES))
    parser.add_argument('--namespace', action='store_true')
    args = parser.parse_args()
    if args.patched:
        sys.path.insert(0, str(ROOT / 'scripts'))
        from build_musl import loader
        args.loader = loader('build')
        args.runtime_loader = loader('runtime')
    out = args.output.resolve()
    providers = dict(static=[str(out / 'static'), None],
                     dynamic=[str(out / 'dynamic'), str(out / 'build-loader')])
    if args.runtime_loader:
        providers['runtime'] = [str(out / 'dynamic'), str(out / 'runtime-loader')]
    if args.compare_glibc:
        providers['glibc'] = [str(out / 'glibc'), None]
    if args.namespace:
        return namespace(out, providers, args.cases)
    assert os.geteuid() == 0, 'private namespaces require root'
    out.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'userspace/tests/net/dns-tcp-probe.c'
    compilers = [('static', args.static_compiler), ('dynamic', args.dynamic_compiler)]
    if args.compare_glibc:
        compilers.append(('glibc', 'gcc'))
    for provider, compiler in compilers:
        command = [compiler, '-O2', '-Wall', '-Wextra', '-Werror', str(source),
                   '-o', str(out / provider)]
        if provider == 'static':
            command.insert(1, '-static')
        if args.patched and provider != 'glibc':
            from build_musl import compiler_args
            command = compiler_args() + command[1:]
        subprocess.run(command, check=True)
    shutil.copyfile(args.loader.resolve(), out / 'build-loader')
    (out / 'build-loader').chmod(0o755)
    if args.runtime_loader:
        shutil.copyfile(args.runtime_loader.resolve(), out / 'runtime-loader')
        (out / 'runtime-loader').chmod(0o755)
    provenance = dict(compiler=subprocess.check_output(['gcc', '--version'], text=True),
                     host_libc=subprocess.check_output(['getconf', 'GNU_LIBC_VERSION'], text=True),
                     kernel=platform.release(),
                     products={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                               for path in out.iterdir() if path.is_file()})
    if args.patched:
        from build_musl import ensure
        provenance['providers'] = {name: json.loads((ensure(name) / 'manifest.json').read_text())
                                   for name in ('build', 'runtime')}
    (out / 'inputs.json').write_text(json.dumps(provenance, indent=2) + '\n')
    (out / 'source.c').write_bytes(source.read_bytes())
    (out / 'runner.py').write_bytes(Path(__file__).read_bytes())
    (out / 'resolv.conf').write_text('nameserver 127.0.0.53\noptions timeout:1 attempts:1\n')
    (out / 'hosts').write_text('127.0.0.1 localhost\n')
    (out / 'namespaces.json').write_text(json.dumps({
        kind: os.readlink('/proc/self/ns/' + kind) for kind in ('mnt', 'net')}))
    provenance['products'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in out.iterdir() if path.is_file() and path.name != 'inputs.json'}
    (out / 'inputs.json').write_text(json.dumps(provenance, indent=2) + '\n')
    before = {name: hashlib.sha256(Path('/etc/' + name).read_bytes()).hexdigest()
              for name in ('hosts', 'resolv.conf')}
    process = subprocess.run(['unshare', '--mount', '--net', '--fork', sys.executable,
                              __file__, *sys.argv[1:], '--namespace'],
                             capture_output=True, text=True, timeout=120)
    (out / 'socket-test.log').write_text(process.stdout + process.stderr)
    print(process.stdout + process.stderr, end='')
    assert before == {name: hashlib.sha256(Path('/etc/' + name).read_bytes()).hexdigest()
                      for name in before}
    if (out / 'results.json').exists():
        evidence = json.loads((out / 'results.json').read_text())
        evidence['host_files_unchanged_sha256'] = before
        (out / 'results.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return process.returncode


if __name__ == '__main__':
    raise SystemExit(main())

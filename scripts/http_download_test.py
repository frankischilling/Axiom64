#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run actual curl downloads as ordinary users against controlled native peers."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

from build_curl import ensure as curl
from build_musl import loader
from build_openssl import ensure as openssl
from fetch import LOCK, ROOT
from http_download.client import commands, verify
from http_download.fixture import image
from http_download.peer import PAYLOAD_SHA256, Peer
from random_administration_test import checked_run, fingerprint
from random_crypto.peer import certificates

NAMES = ('http', 'tls12', 'tls13', 'hostname', 'untrusted', 'expired', 'future')


def snapshot(output):
    names = {'Makefile', 'dependencies.json', 'sources.lock.json', 'ports.lock.json', 'vendor/limine.h'}
    for folder in ('kernel', 'userspace', 'scripts', 'vendor'):
        names.update(path.relative_to(ROOT).as_posix() for path in (ROOT / folder).rglob('*')
            if path.is_file() and path.suffix in ('.c', '.h', '.cpp', '.hpp', '.asm', '.ld', '.py', '.sh', '.patch'))
    inputs = {}
    for name in sorted(names):
        path = ROOT / name
        inputs[name] = fingerprint(path)
        destination = output / 'retained-source' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    (output / 'source-inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    return inputs


def peer_results(peers):
    for name, peer in peers.items():
        value = peer.result
        if value['errors'] or not value['closed']:
            raise RuntimeError('native HTTP peer failed: ' + name + ' ' + repr(value))
        if name == 'http':
            expected = Counter({'/fixed': 2, '/chunked': 1, '/redirect': 1, '/truncated': 1,
                                '/range': 1, '/missing': 1, '/stall': 1, '/small': 1})
            if Counter(row['target'] for row in value['requests']) != expected:
                raise RuntimeError('actual HTTP request inventory differs')
        elif name in ('tls12', 'tls13'):
            if (len(value['requests']) != 1 or value['requests'][0]['target'] != '/fixed' or
                value['requests'][0]['tls_version'] != ('TLSv1.2' if name == 'tls12' else 'TLSv1.3') or
                not value['requests'][0].get('sent') or value['rejected_handshakes'] or
                value['rejected_after_handshake']):
                raise RuntimeError('actual authenticated HTTP/TLS exchange differs: ' + name)
        elif value['requests'] or len(value['rejected_handshakes']) + len(value['rejected_after_handshake']) != 1:
            raise RuntimeError('invalid certificate received HTTP application data: ' + name)
    return {name: peer.result for name, peer in peers.items()}


def native(case, provider, linkage, directory, certs, peers, timeout):
    if os.geteuid() != 0:
        raise RuntimeError('ordinary-user native comparisons need the private root build session')
    with tempfile.TemporaryDirectory(prefix='axiom64-http-client-') as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        binary = work / 'bin'
        binary.mkdir(mode=0o755)
        sources = {'curl': directory / linkage / 'stage/usr/bin/curl',
                   'busybox': ROOT / ('build/busybox-' + LOCK['busybox']['version'] + '/busybox')}
        if linkage == 'dynamic':
            sources['libcurl.so.4'] = directory / 'dynamic/stage/usr/lib/libcurl.so.4'
            tls = openssl(provider) / 'dynamic/stage/usr/lib'
            sources.update({name: tls / name for name in ('libssl.so.3', 'libcrypto.so.3')})
            if provider != 'native':
                sources['loader'] = loader(provider)
                sources['libc.musl-x86_64.so.1'] = loader(provider)
                sources['libc.so'] = loader(provider)
        for name, path in sources.items():
            target = binary / name
            shutil.copyfile(path, target)
            target.chmod(0o755)
            if fingerprint(target) != fingerprint(path):
                raise RuntimeError('native client input changed during accessible copy: ' + name)
        public = work / 'certificates'
        public.mkdir(mode=0o755)
        for name in ('ca.pem', 'untrusted.pem'):
            shutil.copyfile(certs / name, public / name)
            (public / name).chmod(0o644)
        output = work / 'output'
        output.mkdir(mode=0o700)
        os.chown(output, 60011, 60011)
        (output / 'deny').mkdir(mode=0o500)
        executable = [str(binary / 'curl')]
        if linkage == 'dynamic' and provider != 'native':
            executable.insert(0, str(binary / 'loader'))
        script, expected = commands(executable, binary / 'busybox', public / 'ca.pem',
            public / 'untrusted.pem', peers, '127.0.0.1', output)
        command_file = work / 'commands.sh'
        command_file.write_text('export LD_LIBRARY_PATH=' + shlex.quote(str(binary)) + '\n' + script)
        command_file.chmod(0o644)
        shutil.copyfile(command_file, case / 'commands.sh')
        command = ['unshare', '--pid', '--fork', '--kill-child', '--', 'setpriv',
                   '--reuid', '60011', '--regid', '60011', '--clear-groups',
                   'env', '-u', 'LD_PRELOAD', 'LC_ALL=C', 'sh', str(command_file)]
        process, text = checked_run(command, case / 'native.log', timeout)
        checks = verify(text, expected)
        if process['returncode'] != 0 or process['timed_out']:
            raise RuntimeError('native download command failed: ' + repr(process))
        exports = {}
        for name in ('fixed.bin', 'chunked.bin', 'redirect.bin', 'resumed.bin', 'tls12.bin', 'tls13.bin'):
            path = output / name
            metadata = path.stat()
            record = dict(**fingerprint(path), uid=metadata.st_uid, gid=metadata.st_gid,
                          mode=stat.S_IMODE(metadata.st_mode))
            if record['sha256'] != PAYLOAD_SHA256 or (record['uid'], record['gid'], record['mode']) != (60011, 60011, 0o600):
                raise RuntimeError('native downloaded file bytes or ownership differ: ' + name)
            exports[name] = record
        for label, expected_status in expected.items():
            if expected_status and ('curl: (' + str(expected_status) + ')') not in (output / (label+'.stderr')).read_text():
                raise RuntimeError('actual failure lacks the useful curl diagnostic: ' + label)
        if (output / 'deny/forbidden.bin').exists():
            raise RuntimeError('ordinary client wrote into the protected output directory')
        shutil.copytree(output, case / 'exports', symlinks=True)
        return dict(process=process, checks=checks, exports=exports,
                    accessible_inputs={name: fingerprint(path) for name, path in sources.items()})


def guest(case, provider, linkage, firmware, transport, directory, certs, peers, timeout):
    iso, expected = image(case, provider, linkage, directory, certs, peers)
    command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
        '-nic', 'none', '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio',
        '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04']
    captures = []
    for lane in (0, 1):
        capture = case / f'lane{lane}.pcap'
        model = ('virtio-net-pci,' + ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on')) if lane == 0 else 'e1000'
        command += ['-netdev', f'user,id=net{lane},net=10.23.{lane+1}.0/24,host=10.23.{lane+1}.1',
                    '-device', model + f',netdev=net{lane},mac=52:54:00:65:00:0{lane}',
                    '-object', f'filter-dump,id=capture{lane},netdev=net{lane},file={capture}']
        captures.append(capture)
    firmware_inputs = {}
    if firmware == 'uefi':
        variables = case / 'VARS.fd'
        shutil.copy2('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                    '-drive', 'if=pflash,format=raw,file='+str(variables)]
        firmware_inputs = {name: fingerprint(Path('/usr/share/OVMF') / name)
                          for name in ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd')}
    process, text = checked_run(command, case / 'guest.log', timeout)
    checks = {}
    for lane in (0, 1):
        parts = re.findall(r'^DOWNLOAD_LANE_BEGIN '+str(lane)+r'\r?\n(.*?)^DOWNLOAD_LANE_END '+str(lane)+r'\r?$', text, re.S | re.M)
        if len(parts) != 1:
            raise RuntimeError('guest did not complete both actual adapter clients: ' + str(lane))
        checks[lane] = verify(parts[0], expected[lane])
    if process['returncode'] != 1 or process['timed_out']:
        raise RuntimeError('guest download process failed: ' + repr(process))
    return dict(process=process, checks=checks, image=fingerprint(iso),
                captures={path.name: fingerprint(path) for path in captures},
                firmware_inputs=firmware_inputs, independent_capture_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'all'), default='all')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/http-downloads')
    args = parser.parse_args()
    if not args.native and args.provider == 'native':
        parser.error('native glibc products run only with --native')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    profiles = (('build', 'runtime', 'native') if args.native else ('build', 'runtime')) if args.provider == 'all' else (args.provider,)
    providers = {name: curl(name) for name in profiles}
    prepare = ['make', '-s', '-j2', 'busybox']
    if not args.native:
        prepare += ['build/axiom64.elf', 'build/init']
    subprocess.run(prepare, cwd=ROOT, check=True)
    inputs = snapshot(output)
    for name, directory in providers.items():
        shutil.copyfile(directory / 'manifest.json', output / ('curl-'+name+'-manifest.json'))
        shutil.copyfile(openssl(name) / 'manifest.json', output / ('openssl-'+name+'-manifest.json'))
    observer = openssl(profiles[0]) / 'static/stage/usr/bin/openssl'
    certs = output / 'certificates'
    certificates(certs, observer)
    linkages = ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,)
    scenarios = [(name, linkage, 'native', 'native') for name in profiles for linkage in linkages] if args.native else [
        (name, linkage, firmware, transport) for name in profiles for linkage in linkages
        for firmware in (('bios', 'uefi') if args.firmware == 'both' else (args.firmware,))
        for transport in (('modern', 'legacy') if args.transport == 'both' else (args.transport,))]
    results = []
    for provider, linkage, firmware, transport in scenarios:
        case = output / '-'.join((provider, linkage, firmware, transport))
        case.mkdir()
        peers = {lane: {name: Peer(name, certs, args.timeout) for name in NAMES}
                 for lane in ((0,) if args.native else (0, 1))}
        row = dict(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                   curl_manifest=fingerprint(providers[provider] / 'manifest.json'), passed=False)
        try:
            row.update(native(case, provider, linkage, providers[provider], certs, peers[0], args.timeout)
                if args.native else guest(case, provider, linkage, firmware, transport,
                                         providers[provider], certs, peers, args.timeout))
            for lane in peers:
                for peer in peers[lane].values():
                    peer.close()
            row['peers'] = {lane: peer_results(group) for lane, group in peers.items()}
            row['passed'] = True
        except BaseException as error:
            row['error'] = repr(error)
            raise
        finally:
            cleanup_errors = []
            for lane, group in peers.items():
                for name, peer in group.items():
                    if not peer.result['closed']:
                        try:
                            peer.close()
                        except BaseException as error:
                            cleanup_errors.append(dict(lane=lane, peer=name, error=repr(error)))
            if cleanup_errors:
                row['cleanup_errors'] = cleanup_errors
                row['passed'] = False
            row['peers'] = {lane: {name: peer.result for name, peer in group.items()}
                            for lane, group in peers.items()}
            results.append(row)
            (case / 'result.json').write_text(json.dumps(row, indent=2)+'\n')
            (output / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
            if cleanup_errors:
                raise RuntimeError('HTTP peer cleanup failed after retaining evidence: ' +
                                   repr(cleanup_errors))
        print('HTTP_DOWNLOAD_CASE_PASS ' + case.name, flush=True)
    if inputs != {name: fingerprint(ROOT / name) for name in inputs}:
        raise RuntimeError('download source inputs changed during actual execution')
    (output / 'receipt.json').write_text(json.dumps(dict(passed=True, profiles=len(results),
        native=args.native, source_inputs=len(inputs), source_inputs_unchanged=True,
        full_issue_acceptance=False), indent=2)+'\n')


if __name__ == '__main__':
    main()

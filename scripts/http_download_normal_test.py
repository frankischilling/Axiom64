#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify real authenticated DHCP-to-download sessions and fresh-kernel persistence."""
import argparse
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess

from account_normal_test import create_disk, write_cpio
from build_curl import ensure as curl
from build_musl import loader
from build_openssl import ensure as openssl
from fetch import ROOT
from http_download.audit import fingerprint
from http_download.normal_boot import boot
from http_download.normal_fixture import entries, exports, image
from http_download.normal_peer import Network, certificate_fixture, verify_peers
from http_download.normal_wire import verify as verify_wire
from http_download_test import snapshot
from tcp_fault_capture import require


def cell(directory, original, providers, runtimes, certificates, firmware, transport,
         timeout=180, storage='both', *, provider, linkage):
    require(provider in ('build', 'runtime'), 'explicit normal-session libc provider')
    require(linkage in ('static', 'dynamic'), 'explicit normal-session client linkage')
    profiles = (provider+'-'+linkage,)
    directory.mkdir()
    network_directory = directory / 'network'
    network_directory.mkdir()
    network = Network(network_directory, certificates, 3*timeout+180)
    result = dict(provider=provider, linkage=linkage, firmware=firmware, transport=transport,
                  curl_profiles=list(profiles), passed=False, phases=[])
    try:
        files, trust_hash = entries(original, providers, runtimes, network, certificates, directory, profiles)
        products = json.loads((directory / 'client-products.json').read_text())
        archive = directory / 'root.cpio'
        write_cpio(archive, files)
        result.update(normal_rootfs=fingerprint(original), fixture_rootfs=fingerprint(archive),
                      administrator_trust_sha256=trust_hash)
        if storage in ('ram', 'both'):
            iso = image(directory / 'ram-image', archive)
            row = boot(directory / 'ram', iso, network, firmware, transport, True, timeout=timeout, profiles=profiles)
            result['phases'].append(dict(phase='ram', **row))
            (directory / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
        if storage in ('ext2', 'both'):
            disk = directory / 'root.ext2'
            create_disk(disk, files)
            iso = image(directory / 'disk-image', archive, True)
            previous = None
            for label, fresh in (('create', True), ('reboot', False)):
                row = boot(directory / label, iso, network, firmware, transport, fresh, disk, timeout, profiles)
                row['exports'] = exports(disk, directory / (label+'-exports'), trust_hash, profiles, products)
                if previous is not None:
                    require(previous['boot_id'] != row['boot_id'], 'two actual distinct normal kernels')
                    require(previous['exports']['files'] == row['exports']['files'],
                            'actual persisted download and trust bytes, modes and owners agree across kernels')
                previous = row
                result['phases'].append(dict(phase=label, **row))
                (directory / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        try:
            network.close()
        except BaseException as error:
            result['cleanup_error'] = repr(error)
            result['passed'] = False
            raise
        finally:
            (directory / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
    try:
        require(network.queries and not network.errors and
                {row['name'] for row in network.queries} ==
                {'lane0.axiom64.test', 'lane1.axiom64.test', 'wrong0.axiom64.test',
                 'wrong1.axiom64.test', 'missing.axiom64.test'},
                'actual production DNS success and NXDOMAIN queries observed independently')
        for group in network.peers.values():
            for peer in group.values():
                require(peer.result['closed'] and not peer.result['errors'], 'actual normal native peer completed')
        result['native_application_inventory'] = verify_peers(
            {str(lane): {name:peer.result for name,peer in group.items()} for lane,group in network.peers.items()},
            result['phases'], profiles)
        result['wire'] = verify_wire(directory, result['phases'],
                                    json.loads((network_directory / 'network.json').read_text()))
        result['passed'] = True
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        (directory / 'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', choices=('build', 'runtime', 'all'), default='all')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--storage', choices=('ram', 'ext2', 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/http-download-normal')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('normal DNS namespace and owned ext2 fixtures require the root build session')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    providers = {name: curl(name) for name in ('build', 'runtime')}
    runtimes = {name: dict(loader=loader(name), tls=openssl(name)) for name in providers}
    with (output / 'normal-image-build.log').open('wb') as log:
        subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/rootfs.cpio'], cwd=ROOT,
                       check=True, stdout=log, stderr=subprocess.STDOUT)
    original = ROOT / 'build/rootfs.cpio'
    original_input = fingerprint(original)
    inputs = snapshot(output)
    for name in providers:
        shutil.copyfile(providers[name] / 'manifest.json', output / ('curl-'+name+'-manifest.json'))
        shutil.copyfile(runtimes[name]['tls'] / 'manifest.json', output / ('openssl-'+name+'-manifest.json'))
        shutil.copyfile(runtimes[name]['loader'].parents[2] / 'manifest.json', output / ('musl-'+name+'-manifest.json'))
    certificates = output / 'certificates'
    certificate_fixture(certificates, runtimes['build']['tls'] / 'static/stage/usr/bin/openssl')
    firmwares = ('bios', 'uefi') if args.firmware == 'both' else (args.firmware,)
    transports = ('modern', 'legacy') if args.transport == 'both' else (args.transport,)
    results = []
    selected = ('build', 'runtime') if args.provider == 'all' else (args.provider,)
    linkages = ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,)
    for provider, linkage, firmware, transport in itertools.product(selected, linkages, firmwares, transports):
        name = '-'.join((provider, linkage, firmware, transport))
        result = cell(output / name, original, providers, runtimes, certificates, firmware, transport,
                      args.timeout, args.storage, provider=provider, linkage=linkage)
        results.append(result)
        (output / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
        print('HTTP_NORMAL_DOWNLOAD_CASE_PASS '+name, flush=True)
    require(fingerprint(original) == original_input, 'original normal rootfs remains unchanged')
    require(inputs == {name: fingerprint(ROOT / name) for name in inputs},
            'normal download source inputs remain unchanged during actual execution')
    report = dict(passed=True, hardware_profiles=len(firmwares)*len(transports), provider_profiles=len(results),
                  source_inputs=len(inputs),
                  original_normal_rootfs_unchanged=True, source_inputs_unchanged=True,
                  full_issue_acceptance=False)
    (output / 'receipt.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()

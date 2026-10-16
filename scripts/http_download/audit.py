# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify a selected matrix from retained sources, images, products and packets."""
import hashlib
import itertools
import json
from pathlib import Path, PurePosixPath
import re

from disk_root import archive_entries
from eventfd_client import verify as eventfd
from http_download.client import verify as client
from http_download.log import healthy
from http_download.iso import components
from http_download.wire import verify as wire
from tcp_fault_capture import require


def fingerprint(path):
    return dict(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def owned(root, name):
    path = PurePosixPath(name)
    require(path.as_posix() == name and not path.is_absolute() and path.parts and
            all(part not in ('.', '..') and ':' not in part and '\\' not in part for part in path.parts),
            'bounded relative evidence path')
    target = root.joinpath(*path.parts)
    require(target.resolve().is_relative_to(root.resolve()), 'evidence remains inside the selected corpus')
    return target


def sources(directory, source_root=None):
    inputs = json.loads((directory / 'source-inputs.json').read_text())
    required = {'Makefile', 'sources.lock.json', 'ports.lock.json', 'dependencies.json',
                'scripts/http_download_test.py', 'scripts/http_download/client.py',
                'scripts/http_download/fixture.py', 'scripts/http_download/peer.py'}
    require(required <= set(inputs), 'retained source includes the actual download producer and clients')
    retained = directory / 'retained-source'
    actual = {path.relative_to(retained).as_posix() for path in retained.rglob('*') if path.is_file()}
    require(actual == set(inputs), 'every declared source has actual retained bytes and no undeclared source')
    for name, expected in inputs.items():
        require(fingerprint(owned(retained, name)) == expected, 'actual retained source bytes: '+name)
        if source_root is not None:
            require(fingerprint(owned(source_root, name)) == expected, 'retained source matches supplied source tree: '+name)
    return dict(passed=True, files=len(inputs), manifest=fingerprint(directory / 'source-inputs.json'),
                supplied_source_tree_verified=source_root is not None)


def products(case, row):
    inputs = json.loads((case / 'products.json').read_text())
    required = {'sbin/init', 'bin/busybox', 'usr/bin/curl', 'usr/bin/eventfd-test',
                'lib/ld-musl-x86_64.so.1', 'etc/ssl/test-ca.pem', 'etc/ssl/untrusted-ca.pem',
                'root.cpio', 'image.iso', 'kernel.elf'}
    if row['linkage'] == 'dynamic':
        required.update({'usr/lib/libcurl.so.4', 'usr/lib/libssl.so.3', 'usr/lib/libcrypto.so.3'})
    require(set(inputs) == required, 'all actual selected client, runtime and boot products')
    archive = archive_entries(case / 'root.cpio')
    for name, expected in inputs.items():
        path = owned(case if name in ('root.cpio', 'image.iso', 'kernel.elf') else case / 'products', name)
        require(fingerprint(path) == expected, 'actual retained product bytes: '+name)
        if name not in ('root.cpio', 'image.iso', 'kernel.elf'):
            require(name in archive and len(archive[name][1]) == expected['bytes'] and
                    hashlib.sha256(archive[name][1]).hexdigest() == expected['sha256'],
                    'actual initramfs contains the selected product: '+name)
    require(row['image'] == inputs['image.iso'], 'reported image matches actual retained ISO')
    embedded = components(case / 'image.iso', {name: inputs[name] for name in ('kernel.elf', 'root.cpio')})
    return dict(passed=True, files=len(inputs), manifest=fingerprint(case / 'products.json'),
                initramfs_products_verified=True, iso_embedded_components=embedded)


def guest_log(case, row):
    path = case / 'guest.log'
    require(row['process']['log'] == path.name and fingerprint(path) == row['process']['log_input'],
            'actual retained guest log matches its execution fingerprint')
    data = path.read_bytes()
    health = healthy(data, row['firmware'])
    require(b'AXIOM64_TESTS_PASS' in data and b'AXIOM64_EXIT status=0' in data,
            'actual guest test completion and explicit successful shutdown')
    # Match the original runner's universal-newline view while hashing raw bytes.
    text = path.read_text()
    counters = eventfd(text, strict=True)
    require(counters == row['eventfd'], 'recorded counter result matches the actual guest log')
    expected = dict(fixed=0, chunked=0, redirect=0, truncated=18, resume=0, missing=22,
                    deadline=28, permission=23, tls12=0, tls13=0, hostname=60,
                    untrusted=60, expired=60, future=60)
    checks = {}
    for lane in (0, 1):
        parts = re.findall(r'^DOWNLOAD_LANE_BEGIN '+str(lane)+r'\r?\n(.*?)^DOWNLOAD_LANE_END '+str(lane)+r'\r?$',
                           text, re.S | re.M)
        require(len(parts) == 1, 'both actual guest adapter logs are complete')
        checks[str(lane)] = client(parts[0], expected)
    require(checks == row['checks'], 'reported hashes, statuses and deadlines match actual guest bytes')
    return dict(passed=True, raw=fingerprint(path), health=health, eventfd=counters, clients=checks)


def verify(directory, *, providers=('build', 'runtime'), linkages=('static', 'dynamic'),
           firmwares=('bios', 'uefi'), transports=('modern', 'legacy'), source_root=None):
    expected = set(itertools.product(providers, linkages, firmwares, transports))
    require(expected and len(providers) == len(set(providers)) and set(providers) <= {'build', 'runtime'} and
            len(linkages) == len(set(linkages)) and set(linkages) <= {'static', 'dynamic'} and
            len(firmwares) == len(set(firmwares)) and set(firmwares) <= {'bios', 'uefi'} and
            len(transports) == len(set(transports)) and set(transports) <= {'modern', 'legacy'},
            'explicit valid guest matrix selectors')
    names = {'-'.join(profile) for profile in expected}
    actual = {path.name for path in directory.iterdir() if path.is_dir() and
              path.name.startswith(('build-', 'runtime-'))}
    require(actual == names, 'exact selected provider/linkage/firmware/transport guest matrix')
    rows = json.loads((directory / 'results.json').read_text())
    require(len(rows) == len(expected), 'complete top-level download result inventory')
    profiles = {(row['provider'], row['linkage'], row['firmware'], row['transport']) for row in rows}
    require(profiles == expected, 'all selected profile identities appear exactly once')
    source_report = sources(directory, source_root)
    results = []
    for row in rows:
        profile = '-'.join(row[key] for key in ('provider', 'linkage', 'firmware', 'transport'))
        case = directory / profile
        require(row == json.loads((case / 'result.json').read_text()), 'per-profile and aggregate results agree')
        require(row['passed'] and not row.get('error') and not row.get('cleanup_errors') and
                row['process']['returncode'] == 1 and not row['process']['timed_out'],
                'actual complete guest process without hidden runtime or cleanup failure')
        require(set(row['peers']) == {'0', '1'} and set(row['captures']) == {'lane0.pcap', 'lane1.pcap'},
                'both actual adapters have separate peers and captures')
        product_report = products(case, row)
        log_report = guest_log(case, row)
        captures = []
        for lane in (0, 1):
            capture = case / f'lane{lane}.pcap'
            require(fingerprint(capture) == row['captures'][capture.name], 'recorded actual capture fingerprint')
            captures.append(wire(capture, lane, row['peers'][str(lane)]))
        results.append(dict(profile=profile, passed=True, products=product_report, guest_log=log_report,
                            captures=captures))
    return dict(passed=True, profiles=len(results), captures=2*len(results), tcp_flows=30*len(results),
                sources=source_report, actual_captured_plain_binary_and_resume_bytes=True,
                actual_tls_negotiation_and_encrypted_records=True, tls_plaintext_decryption=False,
                iso_embedded_components_verified=True, full_issue_acceptance=False, rows=results)

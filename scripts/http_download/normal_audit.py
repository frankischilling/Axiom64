# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen normal-session source, product, boot, packet and persistent-disk evidence."""
import hashlib
import itertools
import json
from pathlib import PurePosixPath
import posixpath
import re

from disk_root import archive_entries
from http_download.audit import fingerprint, owned, sources
from http_download.iso import components
from http_download.normal_boot import verify as guest_log
from http_download.normal_fixture import contents, exports
from http_download.normal_peer import verify_peers
from http_download.normal_wire import verify as wire
from tcp_fault_capture import require


def product_hash(manifest, name):
    seen = set()
    while name not in seen and len(seen) < 40:
        seen.add(name)
        if name in manifest['products']:
            return manifest['products'][name]
        target = manifest.get('symlinks', {}).get(name)
        require(target, 'declared producer product or link: '+name)
        name = posixpath.normpath(str(PurePosixPath(name).parent / target))
    raise ValueError('cyclic declared producer link')


def products(directory, case, row):
    archive = archive_entries(case / 'root.cpio')
    inputs = json.loads((case / 'client-products.json').read_text())
    require(fingerprint(case / 'root.cpio') == row['fixture_rootfs'], 'actual normal fixture archive')
    manifests = {}
    for provider in ('build','runtime'):
        group = {}
        for package in ('curl','openssl','musl'):
            path = directory / (package+'-'+provider+'-manifest.json')
            group[package] = json.loads(path.read_text())
            require(group[package]['provider'] == provider, 'explicit normal producer libc provider')
        require(group['curl']['identity_inputs']['libc_manifest_sha256'] ==
                fingerprint(directory / ('musl-'+provider+'-manifest.json'))['sha256'] and
                group['curl']['identity_inputs']['openssl_manifest_sha256'] ==
                fingerprint(directory / ('openssl-'+provider+'-manifest.json'))['sha256'] and
                group['openssl']['libc_identity'] == group['musl']['identity'],
                'normal curl, TLS and libc producer identities agree')
        manifests[provider] = group
    required = {'usr/bin/curl','usr/bin/openssl','lib/ld-musl-x86_64.so.1',
                'usr/lib/libssl.so.3','usr/lib/libcrypto.so.3'}
    for profile in row['curl_profiles']:
        provider,linkage = profile.split('-')
        base = 'usr/share/download-fixture/'+profile
        required.add(base+'/curl')
        if linkage == 'dynamic':
            required.update(base+'/'+name for name in ('loader','lib/libc.so','lib/libc.musl-x86_64.so.1',
                                                       'lib/libcurl.so.4','lib/libssl.so.3','lib/libcrypto.so.3'))
    installed_libcurl = [name for name in inputs if name.startswith('usr/lib/libcurl.so.')]
    require(len(installed_libcurl) == 1, 'one retained regular installed libcurl product')
    required.update(installed_libcurl)
    require(set(inputs) == required, 'complete normal fixture and installed client product inventory')
    for name,expected in inputs.items():
        path = owned(case / 'products',name)
        data = contents(archive,name)
        require(fingerprint(path) == expected and len(data) == expected['bytes'] and
                hashlib.sha256(data).hexdigest() == expected['sha256'], 'actual normal archive product: '+name)
        provider,linkage = 'runtime','dynamic'
        if name.startswith('usr/share/download-fixture/'):
            profile = name.split('/')[3]
            provider,linkage = profile.split('-')
            tail = name.split('/',4)[4]
        else:
            tail = name
        group = manifests[provider]
        if tail in ('loader','lib/libc.so','lib/libc.musl-x86_64.so.1','lib/ld-musl-x86_64.so.1'):
            declared = product_hash(group['musl'],'sysroot/lib/ld-musl-x86_64.so.1')
        elif tail in ('curl','usr/bin/curl'):
            declared = product_hash(group['curl'],linkage+'/stage/usr/bin/curl')
        elif 'libcurl.so.' in tail:
            declared = product_hash(group['curl'],'dynamic/stage/usr/lib/libcurl.so.4')
        elif tail == 'usr/bin/openssl':
            declared = product_hash(group['openssl'],'dynamic/stage/usr/bin/openssl')
        else:
            declared = product_hash(group['openssl'],'dynamic/stage/usr/lib/'+PurePosixPath(tail).name)
        require(declared == expected['sha256'], 'normal product matches its selected producer: '+name)
    return dict(passed=True,files=len(inputs),manifest=fingerprint(case / 'client-products.json'))


def images(case, row, storage):
    results = {}
    for label in (('ram-image','disk-image') if storage == 'both' else
                  ('ram-image',) if storage == 'ram' else ('disk-image',)):
        directory = case / label
        inputs = json.loads((directory / 'inputs.json').read_text())
        require(fingerprint(directory / 'image.iso') == inputs['image'] and
                fingerprint(directory / 'kernel.elf') == inputs['kernel'], 'normal retained image and kernel')
        if label == 'ram-image':
            require(inputs['initramfs'] == row['fixture_rootfs'], 'normal RAM image uses checked fixture archive')
        report = components(directory / 'image.iso',{'kernel.elf':inputs['kernel'],'root.cpio':inputs['initramfs']})
        lines = re.findall(r'^\s*cmdline:\s*(.*)$',report['configuration'],re.M)
        require(len(lines) == 1, 'one explicit normal ISO command line')
        tokens = lines[0].split()
        require('init=/sbin/init' in tokens and 'test' not in tokens and
                (label != 'disk-image' or {'root=/dev/vda','rootfstype=ext2','rootflags=rw'} <= set(tokens)),
                'actual normal PID1 and writable disk-root boot configuration')
        results[label] = report
    return results


def retained_exports(case, phases, actual):
    for phase in phases:
        if phase['phase'] == 'ram':
            continue
        require(phase['exports']['files'] == actual['files'] and
                phase['exports']['strict_fsck_returncode'] == 0, 'actual persistent before/after exports agree')
        for path,expected in actual['files'].items():
            stem = path.strip('/').replace('/','-')
            retained = case / (phase['phase']+'-exports') / (stem+'.bin')
            require(fingerprint(retained) == {key:expected[key] for key in ('bytes','sha256')},
                    'actual retained persistent bytes: '+path)


def verify(directory, output, *, providers=('build','runtime'), linkages=('static','dynamic'), firmwares=('bios','uefi'),
           transports=('modern','legacy'), storage='both', source_root=None):
    output.mkdir(parents=True,exist_ok=False)
    expected = set(itertools.product(providers,linkages,firmwares,transports))
    require(expected and set(providers) <= {'build','runtime'} and set(firmwares) <= {'bios','uefi'} and
            set(linkages) <= {'static','dynamic'} and set(transports) <= {'modern','legacy'},
            'valid explicit normal acceptance matrix')
    actual = {path.name for path in directory.iterdir() if path.is_dir() and
              path.name.startswith(('build-','runtime-'))}
    require(actual == {'-'.join(profile) for profile in expected}, 'complete selected normal provider/hardware matrix')
    report = dict(passed=False,sources=sources(directory,source_root),rows=[])
    rows = json.loads((directory / 'results.json').read_text())
    require(len(rows) == len(expected) and
            {(row['provider'],row['linkage'],row['firmware'],row['transport']) for row in rows} == expected,
            'complete normal result inventory')
    phase_names = ['ram','create','reboot'] if storage == 'both' else ['ram'] if storage == 'ram' else ['create','reboot']
    for row in rows:
        name = '-'.join(row[key] for key in ('provider','linkage','firmware','transport'))
        case = directory / name
        require(row == json.loads((case / 'result.json').read_text()) and row['passed'] and
                not row.get('error') and not row.get('cleanup_error'), 'actual complete normal cell report')
        profiles = [row['provider']+'-'+row['linkage']]
        require(row['curl_profiles'] == profiles and [phase['phase'] for phase in row['phases']] == phase_names,
                'explicit selected normal linkage and every requested RAM/persistent phase')
        retained_products = products(directory,case,row)
        image_report = images(case,row,storage)
        identifiers = []
        for phase in row['phases']:
            folder = case / phase['phase']
            path = folder / 'guest.log'
            require(fingerprint(path) == phase['log'] and phase['curl_profiles'] == profiles,
                    'actual normal log fingerprint and provider identity')
            process = json.loads((folder / 'process.json').read_text())
            require(process['returncode'] == 1 and not process['error'] and
                    phase['deadline_seconds'] == process['deadline_seconds'] == 180 and phase['elapsed_seconds'] <= 180,
                    'actual normal process and unchanged guest deadline')
            observed = guest_log(path.read_bytes(),phase['phase'] != 'reboot',phase['phase'] != 'ram',row['firmware'],profiles)
            require(all(phase[key] == value for key,value in observed.items()), 'normal recorded result matches actual log bytes')
            identifiers.append(observed['boot_id'])
        require(len(set(identifiers)) == len(identifiers), 'all normal phases boot distinct actual kernels')
        network = json.loads((case / 'network/network.json').read_text())
        peer_report = verify_peers(network['peers'],row['phases'],profiles)
        wire_report = wire(case,row['phases'],network)
        current_exports = None
        if storage != 'ram':
            products_record = json.loads((case / 'client-products.json').read_text())
            current_exports = exports(case / 'root.ext2',output / (name+'-final-disk'),
                                      row['administrator_trust_sha256'],profiles,products_record)
            retained_exports(case,row['phases'],current_exports)
        report['rows'].append(dict(profile=name,passed=True,products=retained_products,images=image_report,
                                   peers=peer_report,wire=wire_report,final_disk=current_exports))
    report.update(passed=True,provider_profiles=len(rows),full_issue_acceptance=False)
    (output / 'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

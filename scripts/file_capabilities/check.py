# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit actual receipt fields, frozen Linux policy, ISO bytes and ext2 metadata."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import lzma
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from file_capabilities.common import digest
from file_capabilities.disk import attributes, inode_offset

REJECTED_EA = {name: 117 for name in ('magic', 'zero-refcount', 'excess-refcount', 'missing-reference',
    'too-few-references', 'multiple-blocks', 'reserved-header', 'external-value', 'zero-namespace',
    'empty-user-name', 'embedded-nul', 'bad-sort', 'unaligned-value', 'value-in-names', 'long-value',
    'overlapping-value', 'entry-hash', 'block-hash', 'outside-device', 'metadata-pointer', 'sector-count',
    'data-alias', 'missing-feature', 'unallocated-pointer')}
REJECTED_EA.update({'acl-policy': 95, 'inline-layout': 95})


def require(value, message):
    if not value:
        raise ValueError(message)


def glibc_source(directory, record):
    source = directory / 'inputs/glibc-source'
    releases = list(source.glob('*-InRelease'))
    require(len(releases) == 1, 'one authenticated Ubuntu source suite')
    signed = releases[0]
    subprocess.run(['gpgv', '--keyring', str(source / 'ubuntu-archive-keyring.gpg'), str(signed)],
                   check=True, capture_output=True)
    match = re.search(r'^ ([a-f0-9]{64})\s+(\d+) main/source/Sources.xz$', signed.read_text(), re.M)
    require(match is not None, 'signed Ubuntu Sources checksum')
    index = source / signed.name.replace('-InRelease', '-Sources.xz')
    require(digest(index) == match[1] and index.stat().st_size == int(match[2]), 'authenticated actual Ubuntu source index')
    paragraphs = lzma.decompress(index.read_bytes()).decode().split('\n\n')
    paragraph = next(item + '\n' for item in paragraphs if re.search(r'^Package: glibc$', item, re.M) and
                     re.search(r'^Version: ' + re.escape(record['version']) + '$', item, re.M))
    checksums = re.search(r'^Checksums-Sha256:\n((?: [^\n]+\n)+)', paragraph, re.M)
    require(checksums is not None, 'authenticated glibc source checksums')
    for expected, size, name in (line.split() for line in checksums[1].splitlines()):
        path = source / name
        require(path.is_file() and digest(path) == expected and path.stat().st_size == int(size), 'authenticated actual glibc source file: ' + name)


def rows(text, prefix):
    result = []
    for line in text.splitlines():
        if line.startswith(prefix + ' '):
            tokens = line[len(prefix) + 1:].split()
            require(prefix.endswith('_PASS') or all('=' in token for token in tokens), 'structured receipt fields: ' + prefix)
            fields = [item.split('=', 1) for item in tokens if '=' in item]
            require(all(len(item) == 2 for item in fields), 'complete receipt fields: ' + prefix)
            require(len({item[0] for item in fields}) == len(fields), 'unique receipt keys: ' + prefix)
            result.append(dict(fields))
    return result


def service(row, native, root_bound):
    bits = 2 | (1 << 40)
    # P, E, I, A, secure, dumpability, ruid/euid/gid, NNP, bounding drops.
    policy = {
        'plain': (0, 0, 0, 0, 0, 1, 1001, 1001, 1001, 0, 0),
        'effective': (bits, bits, 0, 0, 1, 0, 1001, 1001, 1001, 0, 0),
        'permitted': (bits, 0, 0, 0, 1, 0, 1001, 1001, 1001, 0, 0),
        'inheritable': (2, 2, 2, 0, 1, 1, 1001, 1001, 1001, 0, 0),
        'inheritable-bounded': (2, 2, 2, 0, 1, 1, 1001, 1001, 1001, 0, 2),
        'ambient-plain': (2, 2, 2, 2, 0, 1, 1001, 1001, 1001, 0, 0),
        'ambient-empty': (0, 0, 2, 0, 0, 1, 1001, 1001, 1001, 0, 0),
        'empty-effective': (0, 0, 0, 0, 1, 1, 1001, 1001, 1001, 0, 0),
        'foreign-root': (2, 2, 2, 2, 0, 1, 1001, 1001, 1001, 0, 0),
        'no-new-privileges': (0, 0, 0, 0, 1, 1, 1001, 1001, 1001, 1, 0),
        'no-new-ambient': (2, 2, 2, 0, 1, 1, 1001, 1001, 1001, 1, 0),
        'bounded-permitted': (2, 0, 0, 0, 1, 0, 1001, 1001, 1001, 0, 1 << 40),
        'noroot-root': (2, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0),
        'setuid-file': (2, 2, 0, 0, 1, 0, 1001, 0, 1001, 0, 0),
        'setgid-file': (2, 2, 0, 0, 1, 0, 1001, 1001, 0, 0, 0),
        'setids-file': (2, 2, 0, 0, 1, 0, 1001, 0, 0, 0, 0),
        'no-new-setuid': (0, 0, 0, 0, 1, 1, 1001, 1001, 1001, 1, 0),
        'no-new-setgid': (0, 0, 0, 0, 1, 1, 1001, 1001, 1001, 1, 0),
        'no-new-setids': (0, 0, 0, 0, 1, 1, 1001, 1001, 1001, 1, 0),
        'root-compatibility': (root_bound, root_bound, 0, 0, 0, 1, 0, 0, 0, 0, 0),
        'unknown-capability-bit': (0, 0, 0, 0, 1, 1, 1001, 1001, 1001, 0, 0),
    }
    for name in ('tool-static', 'tool-dynamic', 'persisted', 'installed-runtime'):
        policy[name] = policy['effective']
    for name in ('nosuid', 'nosuid-empty', 'wire-v3-foreign', 'wire-root-overflow'):
        policy[name] = policy['plain']
    for name in ('wire-v1', 'wire-v2', 'wire-v3-root0', 'wire-unused-flags'):
        policy[name] = (2, 2, 0, 0, 1, 0, 1001, 1001, 1001, 0, 0)
    name = row['name']
    require(name in policy, 'known actual exec service: ' + name)
    p, e, i, a, secure, dump, ruid, euid, gid, nnp, dropped = policy[name]
    for key, expected in [('permitted', p), ('effective', e), ('inheritable', i), ('ambient', a),
                          ('bounding', root_bound & ~dropped)]:
        require(int(row[key], 16) == expected, 'actual exec ' + key + ': ' + name)
    for key, expected in [('ruid', ruid), ('euid', euid), ('suid', euid), ('rgid', ruid),
                          ('egid', gid), ('sgid', gid), ('secure', secure), ('keepcaps', 0),
                          ('no_new_privileges', nnp)]:
        require(int(row[key]) == expected, 'actual exec ' + key + ': ' + name)
    actual_dump = int(row['dumpable'])
    require(actual_dump == dump or (native and dump == 0 and actual_dump == 2), 'actual exec dumpability: ' + name)
    require(row['expected_dumpable'] == ('normal' if dump else 'restricted'), 'frozen dumpability class: ' + name)


def receipts(text, native=False, full=False, persisted=False, remount=False, ram=False):
    observed = rows(text, 'FILECAP_OBSERVATION')
    require(observed, 'actual syscall observations')
    ids = defaultdict(list)
    for row in observed:
        ids[int(row['pid'])].append(int(row['id']))
        require(row['passed'] == '1' and row['result'] == row['expected'] and row['errno'] == row['expected_errno'],
                'actual syscall result and errno: ' + row['name'])
    errors = {
        1: ('nofollow-user-set', 'trusted-write-admin', 'security-write-admin', 'sticky-directory-owner',
            'setfcap-not-security-admin', 'setfcap-not-trusted-admin', 'unprivileged-setfcap', 'unprivileged-removefcap',
            'exec-irreversible-uid-drop', 'exec-irreversible-cap-drop', 'bounded-effective-exec', 'unprivileged-remount',
            'unprivileged-invalid-root'),
        9: ('bad-fd', 'opath-get', 'opath-list', 'opath-set', 'opath-remove'),
        13: ('user-read-dac', 'user-write-dac'),
        14: ('fault-name', 'fault-path', 'fault-input', 'fault-output', 'fault-list'),
        17: ('create-present', 'create-replace-present'),
        22: ('invalid-flags', 'empty-suffix', 'empty-capability-get', 'invalid-capability-length',
             'revision1-write-denied', 'unknown-revision', 'unknown-capability-flags', 'invalid-namespace-root', 'unprivileged-invalid-flags'),
        30: ('readonly-path-set', 'readonly-nofollow-set', 'readonly-fd-set', 'readonly-capability-set',
             'readonly-invalid-capability', 'readonly-unknown-namespace', 'readonly-path-remove',
             'readonly-nofollow-remove', 'readonly-fd-remove'),
        34: ('short-value', 'empty-name', 'long-name', 'short-list', 'max-value-short'),
        61: ('missing-get', 'missing-remove', 'replace-absent', 'create-replace-absent', 'nofollow-user-get',
             'trusted-read-hidden', 'content-clears-marking', 'cow-owner-strips-mark', 'full-volume-unset',
             'full-volume-no-file-capability'),
        95: ('unknown-namespace',), 7: ('large-value', 'max-value-overflow'), 2: ('unlinked-path',), 8: ('failed-elf-exec',),
        5: ('injected-xattr-io',), 28: ('ext2-block-full', 'ext2-value-too-large', 'full-volume-attribute', 'full-volume-file-capability'),
    }
    frozen_errors = {name: error for error, names in errors.items() for name in names}
    for row in observed:
        if row['name'] in frozen_errors:
            require(row['result'] == '-1' and int(row['errno']) == frozen_errors[row['name']], 'frozen Linux errno: ' + row['name'])
    services = rows(text, 'FILECAP_EXEC_RECEIPT')
    service_pids = {int(row['pid']) for row in services}
    for pid, sequence in ids.items():
        segments = [[]]
        for number in sequence:
            if segments[-1] and number == 1:
                require(pid in service_pids and len(segments) == 1, 'counter reset belongs to an actual exec')
                segments.append([])
            segments[-1].append(number)
        for segment in segments:
            require(segment[0] > 0 and segment == list(range(segment[0], segment[0] + len(segment))),
                    'complete nonduplicated syscall sequence')
        if len(segments) == 2:
            require(segments[-1] == [1, 2], 'complete observations after exec resets the process image')
    passes = Counter(row['name'] for row in rows(text, 'FILECAP_EXEC_SERVICE_PASS'))
    require(Counter(row['name'] for row in services) == passes, 'one completed service per actual exec receipt')
    root_bound = int(services[0]['bounding'], 16) if services else (1 << 41) - 1
    require(root_bound & (2 | (1 << 40)) == 2 | (1 << 40) and root_bound >> 41 == 0, 'supported initial bounding set')
    for row in services:
        service(row, native, root_bound)
    failed_states = defaultdict(list)
    for row in rows(text, 'FILECAP_FAILED_CREDENTIAL_RECEIPT'):
        failed_states[row['name']].append(row)
    for name, pair in failed_states.items():
        require(len(pair) == 2 and [row['stage'] for row in pair] == ['before', 'after'], 'both actual failed-exec credential snapshots')
        before, after = [dict(row) for row in pair]
        before.pop('stage')
        after.pop('stage')
        require(before == after and before['ruid'] == before['euid'] == before['fsuid'] == '1001', 'failed exec preserves actual identities, caps, flags and dumpability')
    if full:
        names = {'plain', 'effective', 'permitted', 'inheritable', 'inheritable-bounded', 'ambient-plain',
                 'ambient-empty', 'empty-effective', 'foreign-root', 'no-new-privileges', 'bounded-permitted',
                 'noroot-root', 'setuid-file', 'no-new-setuid', 'root-compatibility', 'unknown-capability-bit',
                 'tool-static', 'tool-dynamic', 'nosuid', 'nosuid-empty', 'no-new-ambient', 'setgid-file',
                 'setids-file', 'no-new-setgid', 'no-new-setids'}
        expected = Counter({name: 1 for name in names})
        if persisted:
            expected['persisted'] = 2 if remount else 1
        require(passes == expected, 'all frozen exec cases including nosuid and maintained tools')
        for phase in ('XATTR', 'FORMAT', 'CONTENT', 'ADMIN', 'EXEC', 'TOOLS', 'MOUNT', 'TEST'):
            require('FILECAP_' + phase + '_PASS ' in text, 'complete phase: ' + phase)
        failed = {(row['name'], row['errno']) for row in rows(text, 'FILECAP_FAILED_EXEC_PASS')}
        require(failed == {('bounded-denied', '1'), ('invalid-elf', '8')}, 'both failed exec transactions')
        require(set(failed_states) == {'bounded-denied', 'invalid-elf'}, 'actual before/after failed-exec state receipts')
        required = {'setxattr': (0, 0), 'lsetxattr-regular': (0, 0), 'fsetxattr-readonly-fd': (0, 0),
                    'getxattr': (5, 0), 'lgetxattr-regular': (1, 0), 'fgetxattr': (1, 0),
                    'listxattr': (32, 0), 'llistxattr-regular': (32, 0), 'flistxattr': (32, 0),
                    'removexattr': (0, 0), 'lremovexattr-regular': (0, 0), 'fremovexattr': (0, 0)}
        for name, value in required.items():
            actual = [row for row in observed if row['name'] == name]
            require(len(actual) == 1 and (int(actual[0]['result']), int(actual[0]['errno'])) == value,
                    'all twelve Linux xattr interfaces: ' + name)
        if ram:
            boundary = rows(text, 'FILECAP_RAM_BOUNDARY_PASS')
            require(boundary == [dict(size='65536', bytes_equal='1', tail='165')], 'complete RAM value-size boundary')
            maximum = {'max-value-set': (0, 0), 'max-value-query': (65536, 0),
                       'max-value-short': (-1, 34), 'max-value-overflow': (-1, 7),
                       'max-value-clamped-get': (65536, 0), 'max-value-remove': (0, 0)}
            for name, value in maximum.items():
                actual = [row for row in observed if row['name'] == name]
                require(len(actual) == 1 and (int(actual[0]['result']), int(actual[0]['errno'])) == value,
                        'actual RAM value-size boundary: ' + name)
        tools = rows(text, 'FILECAP_TOOL_RECEIPT')
        require(len(tools) == 16 + (2 if remount else 1 if persisted else 0), 'all upstream tool invocations')
        for row in tools:
            output = bytes.fromhex(row['hex'])
            status = int(row['status'])
            require(len(output) == int(row['bytes']) and status == int(row['expected']), 'actual upstream tool receipt')
            require(status in (0, 1) and (status == 0 or b'Operation not permitted' in output), 'actual denied tool diagnostic')
        for linkage in ('static', 'dynamic'):
            outputs = [bytes.fromhex(row['hex']) for row in tools if row['name'] == 'getcap-' + linkage]
            require(b'./tool-service cap_dac_override,cap_checkpoint_restore=ep\n' in outputs and
                    b'./tool-service cap_dac_override,cap_checkpoint_restore=ep [rootid=1000]\n' in outputs and b'' in outputs,
                    'maintained getcap exact marking, root identity and removal')
    return dict(observations=len(observed), services=len(services))


def cpio(raw):
    at, files = 0, {}
    while at < len(raw):
        require(raw[at:at + 6] == b'070701', 'newc archive header')
        fields = [int(raw[at + 6 + i * 8:at + 14 + i * 8], 16) for i in range(13)]
        size, length = fields[6], fields[11]
        start = at + 110
        name = raw[start:start + length - 1].decode()
        require(raw[start + length - 1] == 0 and length > 0, 'newc name terminator')
        start = (start + length + 3) & ~3
        require(start + size <= len(raw) and name not in files, 'bounded unique newc entry')
        if name == 'TRAILER!!!':
            return files
        files[name] = raw[start:start + size]
        at = (start + size + 3) & ~3
    raise ValueError('complete newc trailer')


def iso_inputs(directory, run, inputs):
    iso = directory / run['image']
    require(digest(iso) == run['image_sha256'], 'actual tested ISO fingerprint')
    with tempfile.TemporaryDirectory(prefix='filecap-iso-') as temporary:
        target = Path(temporary)
        subprocess.run(['xorriso', '-osirrox', 'on', '-indev', str(iso), '-extract', '/boot/axiom64.elf', str(target / 'kernel'),
                        '-extract', '/boot/rootfs.cpio', str(target / 'rootfs')], check=True, capture_output=True)
        require(digest(target / 'kernel') == inputs['files']['build/axiom64.elf'], 'actual ISO kernel')
        files = cpio((target / 'rootfs').read_bytes())
    for name, source in [('sbin/init', 'build/init'), ('bin/file-capabilities-tests',
                          'build/file-capabilities-' + ('dynamic' if '-dynamic-' in iso.name or iso.name.startswith('axiom64-filecap-dynamic-') else 'static'))]:
        require(hashlib.sha256(files[name]).hexdigest() == inputs['files'][source], 'actual ISO product: ' + name)
    products = inputs['files']
    installed = 'usr/sbin/getcap' in files
    provider = 'runtime' if installed else 'build'
    for name in ('getcap-dynamic', 'setcap-dynamic') if installed else ('getcap-static', 'getcap-dynamic', 'setcap-static', 'setcap-dynamic'):
        source = next(path for path in products if path.startswith('build/libcap/' + provider + '/') and path.endswith('/' + name))
        destination = 'usr/sbin/' + name.removesuffix('-dynamic') if installed else 'bin/' + name
        require(hashlib.sha256(files[destination]).hexdigest() == products[source], 'actual ISO maintained tool: ' + name)
    source = next(path for path in products if path.startswith('build/musl/' + provider + '/') and path.endswith('/ld-musl-x86_64.so.1'))
    require(hashlib.sha256(files['lib/ld-musl-x86_64.so.1']).hexdigest() == products[source], 'actual ISO pinned nested exec loader')


def metadata_bytes(directory, record):
    disk = directory / record['disk']
    data = disk.read_bytes()
    def inode(path):
        stat = subprocess.check_output(['/usr/sbin/debugfs', '-R', 'stat ' + path, str(disk)], stderr=subprocess.DEVNULL).decode()
        match = re.search(r'Inode:\s+(\d+)', stat)
        require(match is not None, 'independent metadata inode: ' + path)
        return int(match[1])
    def values(path):
        return attributes(data, inode_offset(data, inode(path)))
    def payload(path):
        with tempfile.TemporaryDirectory(prefix='filecap-export-') as temporary:
            target = Path(temporary) / 'payload'
            subprocess.run(['/usr/sbin/debugfs', '-R', f'dump {path} "{target}"', str(disk)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            require(target.is_file(), 'independent metadata payload: ' + path)
            return target.read_bytes()
    if record['kind'] == 'shared':
        actual, header = values('/beta')
        require(actual == {(1, b'shared'): b'changed', (1, 'é'.encode()): b'utf8', (9, b'opaque-extra'): b'invisible'} and
                header['references'] == 1, 'independent shared EA copy, opaque bytes and stripped capability')
        linkage = re.search(r'\b(static|dynamic)\b', record['boot']['label'])[1]
        require(payload('/beta') == (directory / 'inputs/build' / ('file-capabilities-' + linkage)).read_bytes(),
                'independent shared inode executable bytes')
        require(payload('/control') == b'unrelated ordinary file bytes\0\xff\n', 'independent unrelated file bytes')
        listing = subprocess.check_output(['/usr/sbin/debugfs', '-R', 'ls -p /', str(disk)], stderr=subprocess.DEVNULL).decode()
        require('/alpha/' not in listing and '/renamed/' not in listing, 'last unlinked shared inode reclaimed')
    elif record['kind'] in ('write-error', 'flush-error', 'full'):
        actual, header = values('/fault')
        require(actual == {(1, b'value'): b'original' if record['kind'] == 'full' else b'recovered',
                           (1, b'unrelated'): b'preserved', (6, b'capability'): struct.pack('<5I', 0x02000001, 2, 0, 0, 0)} and
                header['references'] == 1, 'independent recovered EA transaction and unchanged capabilities')
        require(payload('/fault') == b'unchanged file payload\n', 'independent recovered file payload')
    elif record['kind'] == 'wire':
        expected = {'wire-v1': struct.pack('<3I', 0x01000001, 2, 0),
                    'wire-v2': struct.pack('<5I', 0x02000001, 2, 0, 0, 0),
                    'wire-v3-root0': struct.pack('<6I', 0x03000001, 2, 0, 0, 0, 0),
                    'wire-v3-foreign': struct.pack('<6I', 0x03000001, 2, 0, 0, 0, 1000),
                    'wire-root-overflow': struct.pack('<6I', 0x03000001, 2, 0, 0, 0, 0xffffffff),
                    'wire-unused-flags': struct.pack('<5I', 0x02000003, 2, 0, 0, 0),
                    'wire-version4': struct.pack('<5I', 0x04000001, 2, 0, 0, 0),
                    'wire-truncated': struct.pack('<5I', 0x02000001, 2, 0, 0, 0)[:-1], 'wire-empty': b''}
        for name, value in expected.items():
            actual, _ = values('/' + name)
            require(actual == {(6, b'capability'): value}, 'independent actual on-disk capability word: ' + name)


def check(directory, quick=False, complete=False):
    directory = Path(directory).resolve()
    inputs = json.loads((directory / 'inputs.json').read_text())
    for name, expected in inputs['files'].items():
        path = (directory / 'inputs' / name).resolve()
        require(path.is_relative_to(directory / 'inputs') and digest(path) == expected, 'retained source/product fingerprint: ' + name)
    for name, record in inputs['native_libraries'].items():
        require(digest(directory / 'inputs/native-libraries' / name) == record['sha256'], 'actual native library/notices: ' + name)
    if inputs.get('glibc_source'):
        for name, expected in inputs['glibc_source']['files'].items():
            require(digest(directory / 'inputs/glibc-source' / name) == expected, 'authenticated glibc source: ' + name)
        glibc_source(directory, inputs['glibc_source'])
    results = json.loads((directory / 'results.json').read_text())
    if complete:
        if directory.name == 'native':
            forms = (('tmpfs', ()), ('ext2', (1024, 128, 'default')), ('ext2', (2048, 256, 'default')),
                     ('ext2', (4096, 256, 'default')), ('ext2', (1024, 128, 'original')))
            expected = {(linkage, filesystem, form) for linkage in ('native', 'static', 'dynamic') for filesystem, form in forms}
            actual = {(row['linkage'], row['filesystem'], tuple(row['format'] or ())) for row in results}
            require(len(results) == 15 and actual == expected, 'complete native filesystem/linkage/format matrix')
        elif directory.name == 'guest':
            configurations = {(row['linkage'], row['filesystem'], tuple(row['format'] or ()),
                               row['write']['firmware'], row['write']['transport']) for row in results}
            forms = (('ram', ()), ('ext2', (1024, 128, 'default')), ('ext2', (2048, 256, 'default')),
                     ('ext2', (4096, 256, 'default')), ('ext2', (1024, 128, 'original')))
            expected = {(linkage, filesystem, form, firmware, transport) for linkage in ('static', 'dynamic')
                        for filesystem, form in forms for firmware in ('bios', 'uefi') for transport in ('modern', 'legacy')}
            require(len(results) == 40 and configurations == expected and all('reboot' in row for row in results if row['filesystem'] == 'ext2'),
                    'complete guest format/linkage/firmware/transport and fresh kernel matrix')
        elif directory.name == 'metadata':
            require(len(results) == 22 and Counter(row['kind'] for row in results) ==
                    {'shared': 6, 'rejected': 8, 'wire': 2, 'write-error': 2, 'flush-error': 2, 'full': 2}, 'complete metadata matrix')
            expected = {f'shared-{linkage}-{block}-{inode}-bios-modern' for linkage in ('static', 'dynamic')
                        for block, inode in ((1024, 128), (2048, 256), (4096, 256))}
            expected |= {f'rejected-{linkage}-bios-modern-{group}' for linkage in ('static', 'dynamic') for group in range(4)}
            expected |= {f'{kind}-{linkage}-bios-modern' for linkage in ('static', 'dynamic')
                         for kind in ('wire', 'write-error', 'flush-error', 'full')}
            require({row['boot']['label'] for row in results} == expected, 'every distinct metadata profile')
            actual = Counter((re.search(r'\b(static|dynamic)\b', row['boot']['label'])[1], case['name'])
                             for row in results if row['kind'] == 'rejected' for case in row['cases'])
            require(actual == Counter({(linkage, name): 1 for linkage in ('static', 'dynamic') for name in REJECTED_EA}),
                    'all distinct malformed and unsupported disks for both linkages')
        elif directory.name == 'installed':
            require(len(results) == 4 and {(row['profile'], row['boot']['firmware']) for row in results} ==
                    {(profile, firmware) for profile in ('full', 'desktop') for firmware in ('bios', 'uefi')}, 'both ordinary image profiles and firmware types')
    counters = Counter()
    images = set()
    for record in results:
        runs = [record[key] for key in ('write', 'reboot', 'boot') if key in record]
        native = not runs
        if native:
            runs = [record]
        for run in runs:
            require(run['passed'] and not run['timed_out'] and run['returncode'] == (0 if native else 1), 'original execution result')
            require(0 < run['elapsed_ns'] <= (run['timeout_seconds'] + 2) * 1000000000 and run['started_ns'] > 0, 'original bounded measured deadline')
            text = (directory / run['log']).read_text()
            require(digest(directory / run['log']) == run['log_sha256'], 'retained actual log fingerprint')
            require(not any(marker in text for marker in ('FILECAP_TEST_FAIL ', 'PANIC:', 'FAULT pid=')), 'actual client/kernel failure')
            full = 'FILECAP_TEST_PASS ' in text
            stats = receipts(text, native, full, native or record.get('filesystem') == 'ext2',
                             native and record['filesystem'] == 'ext2', record.get('filesystem') in ('ram', 'tmpfs'))
            counters.update(stats)
            counters['runs'] += 1
            if not native:
                require('AXIOM64_EXIT status=0' in text and 'AXIOM64_TESTS_PASS' in text, 'complete guest exit')
                require('Firmware: ' + run['firmware'].upper() in text, 'actual guest firmware')
                require(digest(directory / run['image']) == run['image_sha256'], 'actual tested ISO fingerprint')
                if run['image'] not in images and not quick:
                    iso_inputs(directory, run, inputs)
                    images.add(run['image'])
        if record.get('kind') == 'rejected':
            require(record['before'] == record['after'], 'rejected disks unchanged')
            text = (directory / record['boot']['log']).read_text()
            rejected = rows(text, 'FILECAP_REJECT_PASS')
            require(len(rejected) == len(record['cases']), 'all actual rejected mount attempts')
            for index, case in enumerate(record['cases']):
                require(case['name'] in REJECTED_EA and case['errno'] == REJECTED_EA[case['name']], 'frozen malformed/unsupported mount errno')
                require(digest(directory / case['disk']) == record['before'][case['disk']], 'rejected actual disk bytes')
                require(rejected[index] == dict(device='/dev/vd' + chr(97 + index), errno=str(case['errno'])), 'actual rejected mount errno')
                counters['rejected_disks'] += 1
        elif record.get('kind') == 'wire':
            text = (directory / record['boot']['log']).read_text()
            cases = rows(text, 'FILECAP_DISK_WIRE_PASS')
            expected = {'wire-v1': (22, 0), 'wire-v2': (0, 0), 'wire-v3-root0': (0, 0), 'wire-v3-foreign': (0, 0),
                        'wire-root-overflow': (75, 0), 'wire-unused-flags': (22, 0), 'wire-version4': (22, 22),
                        'wire-truncated': (22, 22), 'wire-empty': (22, 22)}
            require({row['name']: (int(row['public_errno']), int(row['exec_errno'])) for row in cases} == expected and len(cases) == 9,
                    'all frozen on-disk wire revision/root/flag outcomes')
        elif record.get('kind') in ('write-error', 'flush-error', 'full', 'shared'):
            text = (directory / record['boot']['log']).read_text()
            marker = 'FILECAP_FULL_PASS ' if record['kind'] == 'full' else 'FILECAP_SHARED_PASS ' if record['kind'] == 'shared' else 'FILECAP_IO_RECOVERY_PASS '
            require(marker in text, 'actual metadata failure/lifetime contract')
        elif record.get('kind') == 'installed':
            text = (directory / record['boot']['log']).read_text()
            require('FILECAP_INSTALLED_TOOLS_PASS ' in text, 'actual ordinary-image maintained tools')
            require([row['name'] for row in rows(text, 'FILECAP_EXEC_RECEIPT')] == ['installed-runtime'], 'actual installed-tool capability exec')
            tools = rows(text, 'FILECAP_TOOL_RECEIPT')
            require([row['status'] for row in tools] == ['0', '0', '1', '0', '0'], 'installed tools allowed/denied/removal outcomes')
            require(bytes.fromhex(tools[1]['hex']) == b'./service cap_dac_override,cap_checkpoint_restore=ep\n' and
                    b'Operation not permitted' in bytes.fromhex(tools[2]['hex']) and not tools[-1]['hex'],
                    'actual installed getcap and denied setcap bytes')
            original = cpio((directory / (record['profile'] + '-original.cpio')).read_bytes())
            used = cpio((directory / (record['profile'] + '.cpio')).read_bytes())
            require(original.keys() | {'bin/file-capabilities-tests'} == used.keys() and
                    all(used[name] == value for name, value in original.items() if name != 'etc/net-test.sh'),
                    'ordinary rootfs bytes preserved around the test script/client')
        if 'disk' in record:
            require(digest(directory / record['disk']) == record['disk_sha256'], 'actual accepted disk fingerprint')
            metadata_bytes(directory, record)
            if not quick:
                process = subprocess.run(['/usr/sbin/e2fsck', '-fn', str(directory / record['disk'])], capture_output=True)
                require(process.returncode == 0, 'independent clean accepted ext2 volume')
                counters['fsck'] += 1
        for key in ('host_write', 'host_reboot', 'host'):
            if key not in record:
                continue
            host = record[key]
            disk = directory / host['disk']
            # The after-write copy retains the state before the independent boot.
            if key == 'host_write':
                disk = disk.with_name(disk.stem + '-after-write.img')
            require(digest(disk) == host['disk_sha256'], 'retained persistence disk state')
            values, header = attributes(disk.read_bytes(), inode_offset(disk.read_bytes(), host['inode']), allow_inline=native)
            require(values == {(1, b'binary'): bytes((0, 255, 17, 0, 127)), (1, b'empty'): b'', (4, b'private'): b'secret',
                               (6, b'custom'): b'metadata', (6, b'capability'): struct.pack('<5I', 0x02000001, 2, 0, 1 << 8, 0)},
                    'independent raw persistent attribute bytes')
            require(header['references'] == 1, 'hardlinks count one EA inode reference')
            counters['persistent_states'] += 1
    counters['isos'] = len(images)
    return dict(counters)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directories', nargs='*', type=Path)
    args = parser.parse_args()
    for directory in args.directories or [ROOT / 'build/file-capabilities' / name for name in ('native', 'guest', 'metadata', 'installed')]:
        print('FILECAP_INDEPENDENT_PASS directory=' + directory.name + ' ' + json.dumps(check(directory, complete=not args.directories), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()

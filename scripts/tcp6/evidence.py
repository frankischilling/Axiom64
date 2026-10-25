# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen source, products, boot images and damaged packet evidence independently."""
import copy
import hashlib
import json
import os
import posixpath
from pathlib import Path
import struct
import tempfile
import zipfile
from itertools import product
from ipv4_expiry_capture import read_capture, encode_capture, checksum
from tcp_fixture_inputs import audit_fixture
from tcp6.capture import require, inspect, verify
from tcp6.inputs import digest, write, freeze
from tcp6.observation import bind


def source(directory):
    receipt = json.loads((directory / 'receipt.json').read_text())
    binding = receipt['source']
    require(digest(directory / 'source.zip') == binding['source_zip_sha256'] and
            digest(directory / 'source-inputs.json') == binding['source_inputs_sha256'],
            'exact complete producer source snapshot')
    records = json.loads((directory / 'source-inputs.json').read_text())
    require(len(records) == binding['files'] and records, 'complete nonempty source inventory')
    with zipfile.ZipFile(directory / 'source.zip') as archive:
        require(len(archive.namelist()) == len(records) and set(archive.namelist()) == set(records),
                'source archive exactly matches its inventory')
        for name, fingerprint in records.items():
            require(not Path(name).is_absolute() and '..' not in Path(name).parts and
                    not name.startswith('.local/') and '\\' not in name and
                    hashlib.sha256(archive.read(name)).hexdigest() == fingerprint,
                    'actual public source bytes and bounded archive name')
    return records


def products(directory, profile, sources, native, suite='loss'):
    from tcp6.profiles import definition
    config = definition(suite)
    compiled = json.loads((directory / 'program.inputs.json').read_text())
    require(digest(directory / 'program') == compiled['product']['sha256'] and
            (directory / 'program').stat().st_size == compiled['product']['bytes'],
            'actual executed program matches its compiler product')
    require(('-DTCP_IPV6' in compiled['command']) == (suite == 'loss') and config['source'] in compiled['command'] and
            ('-static' in compiled['command']) == (profile == 'static') and
            compiled['sources'] and all(not name.startswith('/') and '\\' not in name and
            not posixpath.normpath(name).startswith('../') and sources.get(posixpath.normpath(name)) == fingerprint
            for name, fingerprint in compiled['sources'].items()),
            'exact IPv6 client compilation sources and linkage')
    elf = (directory / 'program').read_bytes()
    require(elf[:7] == b'\x7fELF\2\1\1' and struct.unpack_from('<H', elf, 18)[0] == 62,
            'actual x86-64 executable format')
    offset = struct.unpack_from('<Q', elf, 32)[0]
    entry_size, count = struct.unpack_from('<HH', elf, 54)
    require(entry_size == 56 and offset + count * entry_size <= len(elf), 'actual ELF program header bounds')
    interpreters = []
    for at in range(offset, offset + count * entry_size, entry_size):
        if struct.unpack_from('<I', elf, at)[0] == 3:
            begin = struct.unpack_from('<Q', elf, at + 8)[0]
            size = struct.unpack_from('<Q', elf, at + 32)[0]
            require(0 < size < 256 and begin + size <= len(elf), 'ELF interpreter bounds')
            interpreters.append(elf[begin:begin + size])
    require((not interpreters if profile == 'static' else len(interpreters) == 1),
            'actual static/dynamic ELF linkage')
    if profile == 'dynamic':
        require(interpreters == [b'/lib/ld-musl-x86_64.so.1\0'], 'owned target musl interpreter')
    if native:
        fingerprints = json.loads((directory / 'products.json').read_text())
        require(all(Path(name).name == name and digest(directory / name) == fingerprint
                    for name, fingerprint in fingerprints.items()), 'frozen native executable and loader bytes')
        return dict(passed=True, program_sha256=digest(directory / 'program'), image_opened=False)
    saved = json.loads((directory / 'image-audit.json').read_text())
    require(digest(directory / 'image.iso') == saved['audit']['sha256'] and
            saved['executables']['bin/' + config['program']] == digest(directory / 'program') and
            saved['executables']['source/program.inputs.json'] == digest(directory / 'program.inputs.json') and
            digest(directory / 'kernel.elf') == saved['kernel_sha256'], 'exact guest image, kernel and original client')
    reopened = audit_fixture(directory / 'image.iso', saved['kernel_sha256'],
                             saved['executables'], saved['script'].encode())
    return dict(passed=True, program_sha256=digest(directory / 'program'), image_opened=True,
                image=reopened, kernel_sha256=saved['kernel_sha256'])


def damaged(path, lane, log, native, output, statistics=None):
    rows = read_capture(path)
    if native:
        bind(path, rows, statistics)
    inspect(rows, lane, log, native)
    guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
    selected = [n for n, row in enumerate(rows) if row['frame'][12:14] == b'\x86\xdd' and
                len(row['frame']) >= 74 and row['frame'][20] == 6]
    outgoing = [n for n in selected if rows[n]['frame'][6:12] == guest]
    data = [n for n in outgoing if len(rows[n]['frame']) > 54 + (rows[n]['frame'][66] >> 4) * 4]
    syns = [n for n in outgoing if rows[n]['frame'][67] & 2]
    require(len(data) >= 2 and len(syns) >= 2, 'original retransmission controls available')
    variants = {}
    def altered(name, index, mutate, repair=False):
        changed = copy.deepcopy(rows)
        frame = bytearray(changed[index]['frame'])
        mutate(frame)
        if repair:
            length = int.from_bytes(frame[18:20], 'big')
            frame[70:72] = b'\0\0'
            frame[70:72] = struct.pack('!H', checksum(frame[22:54] +
                                      struct.pack('!I3xB', length, 6) + frame[54:54 + length]))
        changed[index]['frame'] = bytes(frame)
        variants[name] = changed, log
    altered('checksum', data[0], lambda frame: frame.__setitem__(70, frame[70] ^ 1))
    altered('full-address', data[0], lambda frame: frame.__setitem__(23, frame[23] ^ 64), True)
    altered('ethernet-owner', data[0], lambda frame: frame.__setitem__(0, frame[0] ^ 2), True)
    altered('payload', data[0], lambda frame: frame.__setitem__(54 + (frame[66] >> 4) * 4,
             frame[54 + (frame[66] >> 4) * 4] ^ 1), True)
    altered('tcp-header', data[0], lambda frame: frame.__setitem__(66, 0xf0))
    acknowledgments = [n for n in selected if rows[n]['frame'][6:12] != guest and
                       rows[n]['frame'][67] & 16]
    altered('future-ack', acknowledgments[0], lambda frame: frame.__setitem__(slice(62, 66),
             ((int.from_bytes(frame[62:66], 'big') + (1 << 30)) & 0xffffffff).to_bytes(4, 'big')), True)
    variants['missing-active-flow'] = [row for n, row in enumerate(rows) if n not in selected or
        int.from_bytes(row['frame'][54:56], 'big') != 44000 + lane and
        int.from_bytes(row['frame'][56:58], 'big') != 44000 + lane], log
    changed = copy.deepcopy(rows)
    if native:
        changed[syns[1]]['arrival_lower_ns'] = changed[syns[0]]['arrival_upper_ns'] + 1000000
        changed[syns[1]]['arrival_upper_ns'] = changed[syns[1]]['arrival_lower_ns']
    else:
        changed[syns[1]]['ns'] = changed[syns[0]]['ns'] + 1000000
    variants['short-real-deadline'] = changed, log
    variants['missing-completion'] = rows, log.replace('TCP6_FAULT_PASS flows=4 bytes_each=65536', '')
    archive_path = output / (path.stem + '-damaged.zip')
    clock_controls = {}
    if native:
        original_clocks = [json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()]
        for name in ('arrival-order', 'missing-arrival'):
            changed = copy.deepcopy(original_clocks)
            if name == 'arrival-order':
                changed[0]['arrival_lower_ns'] = changed[0]['receipt_monotonic_after_ns'] + 1
            else:
                changed.pop()
            encoded = ''.join(json.dumps(row) + '\n' for row in changed).encode()
            changed_statistics = copy.deepcopy(statistics)
            changed_statistics.update(monotonic_receipts=name + '.clocks.jsonl',
                                      monotonic_receipts_sha256=hashlib.sha256(encoded).hexdigest())
            clock_controls[name] = encoded, changed_statistics
    with zipfile.ZipFile(archive_path, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, (changed, text) in variants.items():
            archive.writestr(name + '.pcap', encode_capture(changed))
            archive.writestr(name + '.log', text)
            archive.writestr(name + '.bounds.json', json.dumps([
                [row.get('arrival_lower_ns'), row.get('arrival_upper_ns')] for row in changed]))
        for name, (encoded, changed_statistics) in clock_controls.items():
            archive.writestr(name + '.pcap', path.read_bytes())
            archive.writestr(name + '.clocks.jsonl', encoded)
            archive.writestr(name + '.statistics.json', json.dumps(changed_statistics))
    rejected = []
    # Close the writer, reopen the ZIP, and parse newly opened files for every case.
    with zipfile.ZipFile(archive_path) as archive, tempfile.TemporaryDirectory(prefix='axiom64-tcp6-damaged-') as temporary:
        for name in variants:
            reopened = Path(temporary) / (name + '.pcap')
            reopened.write_bytes(archive.read(name + '.pcap'))
            changed = read_capture(reopened)
            bounds = json.loads(archive.read(name + '.bounds.json'))
            require(len(bounds) == len(changed), 'serialized control arrival count')
            for row, (lower, upper) in zip(changed, bounds):
                if lower is not None:
                    row.update(arrival_lower_ns=lower, arrival_upper_ns=upper)
            try:
                inspect(changed, lane, archive.read(name + '.log').decode(), native)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('reader accepted freshly reopened damaged evidence: ' + name)
        for name in clock_controls:
            reopened = Path(temporary) / (name + '.pcap')
            reopened.write_bytes(archive.read(name + '.pcap'))
            reopened.with_suffix('.clocks.jsonl').write_bytes(archive.read(name + '.clocks.jsonl'))
            try:
                bind(reopened, read_capture(reopened), json.loads(archive.read(name + '.statistics.json')))
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('reader accepted reopened damaged packet clocks: ' + name)
    return dict(passed=True, rejected=rejected, archive_sha256=digest(archive_path))


def damaged_products(directory, profile, sources, native, output, suite='loss'):
    from tcp6.profiles import definition
    source_name = definition(suite)['source']
    names = ['program', 'program.inputs.json', *(['loader'] if profile == 'dynamic' else [])]
    original = {name: (directory / name).read_bytes() for name in names}
    original['products.json'] = json.dumps({name: hashlib.sha256(data).hexdigest()
                                          for name, data in original.items()}).encode()
    variants = {}
    for name in ('program-bytes', 'source-binding', 'source-escape', 'linkage', 'compiler-size', 'elf-format'):
        files = original.copy()
        compiled = json.loads(files['program.inputs.json'])
        if name == 'program-bytes':
            files['program'] = files['program'][:-1] + bytes([files['program'][-1] ^ 1])
        elif name == 'source-binding':
            compiled['sources'][source_name] = '0' * 64
        elif name == 'source-escape':
            compiled['sources']['../' + source_name] = compiled['sources'].pop(source_name)
        elif name == 'linkage':
            if '-static' in compiled['command']:
                compiled['command'].remove('-static')
            else:
                compiled['command'].insert(1, '-static')
        elif name == 'compiler-size':
            compiled['product']['bytes'] += 1
        else:
            changed = bytearray(files['program'])
            changed[4] = 1
            files['program'] = bytes(changed)
            compiled['product']['sha256'] = hashlib.sha256(files['program']).hexdigest()
        files['program.inputs.json'] = json.dumps(compiled).encode()
        # Reseal the outer product list: each case must reach the semantic reader.
        files['products.json'] = json.dumps({key: hashlib.sha256(value).hexdigest()
            for key, value in files.items() if key != 'products.json'}).encode()
        variants[name] = files
    if not native:
        files = original.copy()
        image = json.loads((directory / 'image-audit.json').read_text())
        image['executables']['sbin/init'] = '0' * 64
        files['image-audit.json'] = json.dumps(image).encode()
        variants['actual-iso-executable'] = files
    path = output / (profile + '-damaged-products.zip')
    with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, files in variants.items():
            for filename, data in files.items():
                archive.writestr(name + '/' + filename, data)
    rejected = []
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory(prefix='axiom64-tcp6-product-') as scratch:
        for name, files in variants.items():
            case = Path(scratch) / name
            case.mkdir()
            for filename in files:
                (case / filename).write_bytes(archive.read(name + '/' + filename))
            image_control = name == 'actual-iso-executable'
            if image_control:
                # Immutable hard links avoid copying a whole retained boot image.
                # The reader only opens these products; no control writes to them.
                os.link(directory / 'image.iso', case / 'image.iso')
                os.link(directory / 'kernel.elf', case / 'kernel.elf')
            try:
                products(case, profile, sources, native=not image_control, suite=suite)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('reader accepted reopened damaged product: ' + name)
    return dict(passed=True, rejected=rejected, archive_sha256=digest(path))


def matrix_shape(rows, expected=None):
    native = all('firmware' not in row for row in rows)
    full = set((profile, None, None) for profile in ('native', 'static', 'dynamic')) if native else set(
        product(('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy')))
    expected = full if expected is None else set(expected)
    actual = [(row['profile'], row.get('firmware'), row.get('transport')) for row in rows]
    require(expected and expected <= full and len(actual) == len(expected) and set(actual) == expected,
            'every selected linkage, firmware and transport occurs exactly once')
    return expected == full


def damaged_matrix(rows, expected, output):
    missing = copy.deepcopy(rows[:-1])
    duplicate = copy.deepcopy(rows)
    duplicate[-1] = duplicate[0]
    unknown = copy.deepcopy(rows)
    unknown[0]['profile'] = 'unsupported'
    variants = dict(missing=missing, duplicate=duplicate, unknown=unknown)
    path = output / 'damaged-matrix.zip'
    with zipfile.ZipFile(path, 'x', zipfile.ZIP_DEFLATED) as archive:
        for name, changed in variants.items():
            archive.writestr(name + '.json', json.dumps(changed))
    rejected = []
    with zipfile.ZipFile(path) as archive:
        for name in variants:
            try:
                matrix_shape(json.loads(archive.read(name + '.json')), expected)
            except ValueError as failure:
                rejected.append(dict(name=name, reason=str(failure)))
            else:
                raise ValueError('reader accepted reopened incomplete matrix: ' + name)
    return dict(rejected=rejected, archive_sha256=digest(path))


def audit(directory, output=None, expected=None):
    audit_output = output or directory / 'audit'
    audit_output.mkdir(parents=True, exist_ok=False)
    reader_source = freeze(audit_output)
    sources = source(directory)
    matrix = json.loads((directory / 'receipt.json').read_text())
    from tcp6.profiles import definition
    suite = matrix.get('suite', 'loss')
    config = definition(suite)
    require(matrix['results'] and matrix['passed'] and matrix.get('complete') is True,
            'complete successful producer observations exist')
    full_matrix = matrix_shape(matrix['results'], expected)
    selection = [(row['profile'], row.get('firmware'), row.get('transport')) for row in matrix['results']]
    matrix_controls = damaged_matrix(matrix['results'], selection, audit_output) if len(selection) > 1 else None
    rows, product_controls = [], {}
    for item in matrix['results']:
        profile = item['profile']
        case = directory / profile
        native = 'firmware' not in item
        product = products(case, profile, sources, native, suite)
        if profile not in product_controls:
            product_controls[profile] = damaged_products(case, profile, sources, native, audit_output, suite)
        output = case if native else case / (item['firmware'] + '-' + item['transport'])
        controls = audit_output / (profile + ('-native' if native else '-' + item['firmware'] + '-' + item['transport']))
        controls.mkdir()
        saved = json.loads((output / 'receipt.json').read_text())
        log = (output / ('client.log' if native else 'guest.log')).read_text()
        require(saved['passed'] and saved['independent_capture_audited'], 'independent original producer capture accepted')
        captures = []
        for lane in range(2):
            statistics = saved['capture_statistics'][lane] if native else None
            path = output / f'lane{lane}.pcap'
            reopened = config['verify'](path, lane, log, native, statistics)
            require(reopened['sha256'] == saved['capture_audits'][lane]['sha256'], 'original accepted packet capture unchanged')
            checker = damaged
            if suite == 'pmtu':
                from tcp6.pmtu_capture import damaged as checker
            captures.append(dict(capture=reopened, negative_controls=checker(path, lane, log, native, controls, statistics)))
        rows.append(dict(profile=profile, native=native, product=product, captures=captures,
                         firmware=item.get('firmware'), transport=item.get('transport')))
    result = dict(passed=True, suite=suite, source_files=len(sources), profiles=len(rows),
                  captures=2 * len(rows), rejected_capture_controls=sum(
                      len(capture['negative_controls']['rejected']) for row in rows for capture in row['captures']),
                  rejected_product_controls=sum(len(row['rejected']) for row in product_controls.values()),
                  product_controls=product_controls, results=rows,
                  full_TCP6_complete=False, full_matrix=full_matrix,
                  matrix_controls=matrix_controls, reader_source=reader_source)
    write(audit_output / 'independent-audit.json', result)
    print(json.dumps({name: value for name, value in result.items()
                      if name not in ('results', 'product_controls')}), flush=True)
    return result

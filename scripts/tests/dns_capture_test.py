# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen actual DNS captures and archived changes to driver evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import sys
from types import SimpleNamespace
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from dns_test import capture_audit


def audit(directory):
    logs = list(directory.glob('dns-*.log'))
    packets = list(directory.glob('dns-*-packets.json'))
    if len(logs) != 1 or len(packets) != 1:
        raise ValueError('one original DNS log and peer record')
    text = logs[0].read_text()
    peers = [SimpleNamespace(**row) for row in json.loads(packets[0].read_text())['peers']]
    return capture_audit(peers, text, directory)


def controls(source, destination):
    destination.mkdir()
    names = [path.name for path in source.iterdir()
             if path.name.endswith(('.pcap', '.log', '-packets.json'))]
    original = {name: (source / name).read_bytes() for name in names}
    log = next(name for name in names if name.endswith('.log'))
    text = original[log].decode()
    mutations = []

    def changed_line(label, prefix, transform, reason, pattern=None):
        lines = text.splitlines(keepends=True)
        selected = next(index for index, line in enumerate(lines)
                        if line.startswith(prefix) and (pattern is None or pattern in line))
        lines[selected] = transform(lines[selected])
        candidate = dict(original)
        candidate[log] = ''.join(lines).encode()
        mutations.append((label, candidate, reason))

    for direction in (0, 4):
        changed_line(f'missing-direction-{direction}', 'DNS_FRAME ', lambda line: '',
                     'exact actual driver receipts', f'packet_type={direction} ')
    changed_line('changed-frame-hash', 'DNS_FRAME ',
                 lambda line: re.sub(r'hash=[0-9a-f]{16}', 'hash=0000000000000000', line),
                 'exact actual driver receipts')
    changed_line('changed-frame-interface', 'DNS_FRAME ',
                 lambda line: line.replace('index=1 ', 'index=2 '),
                 'exact actual driver receipts', 'index=1 ')
    changed_line('changed-link-hash', 'DNS_LINK_FRAME ',
                 lambda line: re.sub(r'hash=[0-9a-f]{16}', 'hash=0000000000000000', line),
                 'every DNS link receipt owns')
    changed_line('changed-link-type', 'DNS_LINK_FRAME ',
                 lambda line: re.sub(r'ether_type=[0-9a-f]{4}', 'ether_type=88b5', line),
                 'every DNS link receipt owns')
    changed_line('malformed-frame', 'DNS_FRAME ', lambda line: line.replace('linkage=', 'library='),
                 'complete IPv4 DNS driver records')
    changed_line('malformed-link', 'DNS_LINK_FRAME ', lambda line: line.replace('length=', 'size='),
                 'complete non-IPv4 DNS driver records')
    changed_line('missing-link', 'DNS_LINK_FRAME ', lambda line: '', 'complete capture with no dropped')
    changed_line('missing-statistics', 'DNS_CAPTURE_PASS ', lambda line: '',
                 'both actual capture sockets')
    changed_line('nonzero-drops', 'DNS_CAPTURE_PASS ', lambda line: line.replace('dropped=0', 'dropped=1'),
                 'complete capture with no dropped')
    changed_line('wrong-statistics', 'DNS_CAPTURE_PASS ',
                 lambda line: re.sub(r'packets=\d+', 'packets=999', line),
                 'complete capture with no dropped')
    changed_line('reversed-clock', 'DNS_FRAME ',
                 lambda line: re.sub(r'monotonic_ms=\d+', 'monotonic_ms=999999999', line),
                 'actual driver receipt clocks are monotonic')
    for lane in range(2):
        candidate = dict(original)
        raw = bytearray(candidate[f'lane{lane}.pcap'])
        struct.pack_into('<I', raw, 28, 1000000)
        candidate[f'lane{lane}.pcap'] = bytes(raw)
        mutations.append((f'invalid-pcap-fraction-{lane}', candidate, 'complete original link Ethernet frame'))
        candidate = dict(original)
        raw = bytearray(candidate[f'lane{lane}.pcap'])
        at = 24
        changed = False
        while at < len(raw):
            size = struct.unpack_from('<I', raw, at + 8)[0]
            if raw[at + 28:at + 30] == b'\x08\x06':
                raw[at + 16 + 20] ^= 1
                changed = True
            at += 16 + size
        if not changed:
            raise ValueError('actual DNS fixture has original ARP records')
        candidate[f'lane{lane}.pcap'] = bytes(raw)
        mutations.append((f'changed-physical-link-{lane}', candidate, 'every DNS link receipt owns'))
        for direction in (0, 4):
            candidate = dict(original)
            raw = bytearray(candidate[f'lane{lane}.pcap'])
            guest = bytes([0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane])
            at = 24
            changed = False
            while at < len(raw):
                size = struct.unpack_from('<I', raw, at + 8)[0]
                frame = raw[at + 16:at + 16 + size]
                if frame[12:14] == b'\x08\x00' and (frame[6:12] == guest) == (direction == 4):
                    raw[at + 16 + size - 1] ^= 1
                    changed = True
                    break
                at += 16 + size
            if not changed:
                raise ValueError('actual DNS fixture has both original IPv4 directions')
            candidate[f'lane{lane}.pcap'] = bytes(raw)
            mutations.append((f'changed-physical-ipv4-{lane}-{direction}', candidate,
                              'every DNS IPv4 observation owns'))
    reports = []
    for label, files, reason in mutations:
        archive = destination / (label + '.zip')
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as output:
            for name, payload in files.items():
                output.writestr(name, payload)
        reopened = destination / label
        reopened.mkdir()
        with zipfile.ZipFile(archive) as saved:
            if saved.testzip() is not None:
                raise ValueError('damaged control archive')
            for name in names:
                (reopened / name).write_bytes(saved.read(name))
        try:
            audit(reopened)
        except (ValueError, RuntimeError) as failure:
            if reason not in str(failure):
                raise AssertionError((label, reason, str(failure))) from failure
            reports.append(dict(label=label, rejected=str(failure),
                                archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
        else:
            raise AssertionError('accepted damaged DNS evidence: ' + label)
        if (not reopened.resolve().is_relative_to(destination.resolve()) or
                {path.name for path in reopened.iterdir()} != set(files) or
                any((reopened / name).read_bytes() != payload for name, payload in files.items())):
            raise ValueError('control cleanup requires an exact owned archive expansion')
        shutil.rmtree(reopened)
    if any((source / name).read_bytes() != payload for name, payload in original.items()):
        raise ValueError('original DNS evidence changed during controls')
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix-results', type=Path)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/dns-capture-controls')
    args = parser.parse_args()
    if args.matrix_results:
        rows = json.loads(args.matrix_results.read_text())
        if len(rows) != 4 or not all(row['passed'] for row in rows):
            raise ValueError('complete successful four-profile DNS matrix')
        sources = [ROOT / row['evidence_directory'] for row in rows]
    else:
        source = ROOT / 'scripts/tests/fixtures/dns-observer'
        manifest = json.loads((source / 'manifest.json').read_text())
        if not all(hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
                   for name, digest in manifest['files'].items()):
            raise ValueError('unchanged actual DNS fixture bytes')
        sources = [source]
    args.directory.mkdir(parents=True, exist_ok=False)
    reports = []
    for index, source in enumerate(sources):
        count = audit(source)
        rejected = controls(source, args.directory / f'profile-{index}')
        reports.append(dict(source=str(source), driver_receipts=count, controls=rejected))
    proof = dict(passed=True, profiles=len(reports), rejected=sum(len(row['controls']) for row in reports),
                 reports=reports)
    (args.directory / 'receipt.json').write_text(json.dumps(proof, indent=2) + '\n')
    print('DNS_CAPTURE_CONTROLS_PASS', proof['profiles'], proof['rejected'], flush=True)


if __name__ == '__main__':
    main()

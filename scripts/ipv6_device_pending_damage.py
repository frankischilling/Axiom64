# SPDX-License-Identifier: GPL-3.0-or-later
"""Close and reopen deliberately corrupted copies of original pending-device captures."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import struct
import tempfile
import zipfile

from ipv6_device_frames import ADDRESS, SUMMARY, LINK, SECRET, STATE, READY
from ipv6_device_pending_capture import inspect
from ipv6_router_capture import checksum, qemu_records, require


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path, rows):
    with path.open('wb') as stream:
        stream.write(b'\xd4\xc3\xb2\xa1' + struct.pack('<HHIIII', 2, 4, 0, 0, 65536, 1))
        for row in rows:
            frame, stamp = row['frame'], row['stamp']
            stream.write(struct.pack('<IIII', stamp // 1000000, stamp % 1000000,
                                     len(frame), len(frame)))
            stream.write(frame)


def _serial(path, physical, row):
    frame = row['frame']
    pattern = re.compile(r'^IPV6_DEVICE_CONTROL lane=' + str(physical) + r' phase=' +
                         str(frame[19]) + r' .*$', re.M)
    flags, preferred, valid = struct.unpack_from('!III', frame, 24)
    replacement = (f'IPV6_DEVICE_CONTROL lane={physical} phase={frame[19]} kind={frame[20]} '
                   f'action={frame[21]} subject={frame[22]} stage={frame[23]} flags={flags:x} '
                   f'preferred={preferred} valid={valid} target={frame[36:52].hex()} '
                   f'observed_ns={int.from_bytes(frame[52:60], "big")}')
    text, count = pattern.subn(replacement, path.read_text())
    require(count == 1, 'one original serial line for coherent damage')
    path.write_text(text)


def damage(case, target, action, state, subject, variant):
    target.mkdir(parents=True)
    for name in ('serial.log', 'lane0.pcap', 'lane1.pcap', 'carrier.json'):
        if (case / name).is_file():
            shutil.copyfile(case / name, target / name)
    packets = [list(qemu_records(target / f'lane{physical}.pcap')) for physical in range(2)]
    for rows in packets:
        for row in rows:
            row['frame'] = bytearray(row['frame'])
    companion = 1 - subject
    guest = bytes.fromhex(f'5254001234{16 + companion:02x}')
    control_mac = bytes([2, 73, 80, 54, companion, 0])

    def control(kind, stage):
        found = [row for row in packets[companion] if row['frame'][12:14] == b'\x88\xc4' and
                 row['frame'][6:12] == guest and
                 (row['frame'][20], row['frame'][23]) == (kind, stage)]
        require(bool(found), 'original selected damage query')
        return found[0]

    probes = [row for row in packets[subject] if len(row['frame']) == 86 and
              row['frame'][12:14] == b'\x86\xdd' and row['frame'][54] == 135]
    conflicts = [row for row in packets[subject] if len(row['frame']) == 86 and
                 row['frame'][12:14] == b'\x86\xdd' and row['frame'][54] == 136]
    if variant == 'bad-ACK':
        row = next(row for row in packets[companion] if
                   row['frame'][12:14] == b'\x88\xc4' and row['frame'][6:12] == control_mac)
        row['frame'][-1] = 1
        reason = 'captured complete ordered device ACK'
    elif variant in ('bad-checksum', 'zero-nonce', 'wrong-probe-owner'):
        frame = probes[0]['frame']
        if variant == 'bad-checksum':
            frame[56] ^= 1
            reason = 'captured complete enhanced device DAD probe'
        else:
            if variant == 'zero-nonce':
                frame[80:86] = bytes(6)
                reason = 'fresh nonzero nonce for every actual DAD owner'
            else:
                frame[70] ^= 1
                reason = 'actual first probe precedes initial tentative query'
            frame[56:58] = bytes(2)
            frame[56:58] = struct.pack('!H', checksum(frame[22:54] +
                struct.pack('!I3xB', 32, 58) + frame[54:]))
    elif variant in ('missing-probe', 'missing-conflict'):
        packets[subject].remove(probes[0] if variant == 'missing-probe' else conflicts[0])
        reason = ('exact initial and restored physical probe count' if variant == 'missing-probe'
                  else 'exact selected physical conflict count')
    elif variant in ('route-count', 'owner-flags', 'link-flags', 'secret'):
        kind, stage, offset, mask, reason = {
            'route-count': (SUMMARY, 0, 27, 1, 'complete address and connected route inventory'),
            'owner-flags': (ADDRESS, 0, 27, 8, 'exact actual owner flags and lifetimes'),
            'link-flags': (LINK, 1, 27, 64, 'raw actual link flags MTU and IPv6 scope'),
            'secret': (SECRET, 0, 51, 1, 'actual stable secret scope lifetime'),
        }[variant]
        row = control(kind, stage)
        row['frame'][offset] ^= mask
        _serial(target / 'serial.log', companion, row)
    elif variant == 'early-ready':
        row = control(READY, 1 if action == 'carrier' else 3)
        if action == 'carrier' and state == 'regenerating':
            row['stamp'] = conflicts[0]['stamp'] + 1999999
            reason = 'regeneration NA to ready real bound: 1999999'
        else:
            probe = probes[-1] if action != 'carrier' or state == 'retrying' else probes[0]
            row['stamp'] = probe['stamp'] + 999999
            reason = ('pending real DAD bound: 999999' if action == 'carrier'
                      else 'restored real DAD bound: 999999')
    elif variant == 'short-window':
        down, row = control(SUMMARY, 1), control(LINK, 2)
        ack = next(value for value in packets[companion] if
                   value['frame'][12:14] == b'\x88\xc4' and
                   value['frame'][6:12] == control_mac and
                   value['frame'][19] == down['frame'][19])
        row['stamp'] = ack['stamp'] + 3999999
        row['frame'][52:60] = (int.from_bytes(down['frame'][52:60], 'big') +
                               3999999999).to_bytes(8, 'big')
        _serial(target / 'serial.log', companion, row)
        reason = 'full original real four second unavailable interval'
    elif variant == 'serial-only':
        row = control(STATE, 0)
        row['frame'][27] ^= 1
        _serial(target / 'serial.log', companion, row)
        row['frame'][27] ^= 1
        reason = 'every serial query equals its captured actual device metadata'
    else:
        raise ValueError('unknown pending device damage')
    for physical, rows in enumerate(packets):
        _write(target / f'lane{physical}.pcap', rows)
    return reason


def controls(case, action, state, archive):
    originals = {path.name: _digest(path) for path in case.iterdir() if path.is_file()}
    outcomes = []
    variants = ['bad-ACK', 'bad-checksum', 'zero-nonce', 'wrong-probe-owner', 'route-count',
                'owner-flags', 'link-flags', 'secret', 'early-ready', 'short-window',
                'serial-only', 'missing-probe']
    if state != 'probing':
        variants.append('missing-conflict')
    if action == 'carrier' and state == 'exhausted':
        variants.remove('early-ready')

    def reject(target):
        try:
            for subject in range(2):
                inspect(target / f'lane{subject}.pcap', subject,
                        (target / 'serial.log').read_text(), action, state)
        except ValueError as error:
            return str(error)
        raise ValueError('corrupted pending-device evidence was accepted')

    with tempfile.TemporaryDirectory(prefix='axiom64-pending-damage-') as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
            for subject in range(2):
                for variant in variants:
                    relative = f'subject{subject}/{variant}'
                    target = root / relative
                    reason = damage(case, target, action, state, subject, variant)
                    require(reject(target) == reason, 'pending damage rejected for expected reason')
                    files = {path.name: _digest(path) for path in target.iterdir() if path.is_file()}
                    for name in files:
                        saved.write(target / name, relative + '/' + name)
                    outcomes.append(dict(case=relative, reason=reason, sha256=files))
        reopened = root / 'reopened'
        with zipfile.ZipFile(archive) as saved:
            require(saved.testzip() is None, 'complete pending damage archive')
            for row in outcomes:
                target = reopened / row['case']
                target.mkdir(parents=True)
                for name, fingerprint in row['sha256'].items():
                    data = saved.read(row['case'] + '/' + name)
                    require(hashlib.sha256(data).hexdigest() == fingerprint,
                            'exact reopened pending damage bytes')
                    (target / name).write_bytes(data)
                require(reject(target) == row['reason'], 'same pending rejection after archive reopen')
    require(all(_digest(case / name) == value for name, value in originals.items()),
            'original pending-device evidence unchanged')
    return outcomes

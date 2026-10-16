# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject changed copies of actual normal-session sources, packets, logs and files."""
import copy
import json
import os
from pathlib import Path
import shutil
import struct

from http_download.audit import fingerprint, sources
from http_download.controls import damaged_capture
from http_download.normal_audit import products, retained_exports, verify as audit
from http_download.normal_boot import verify as guest
from http_download.normal_dns_wire import verify as dns
from http_download.normal_wire import verify as wire
from tcp_capture import checksum
from tcp_fault_capture import require


def changed_lease(raw):
    data = bytearray(raw)
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    at = 24
    while at < len(data):
        length = struct.unpack_from(endian+'I',data,at+8)[0]
        start = at+16
        at = start+length
        frame = data[start:at]
        if len(frame) < 282 or frame[12:14] != b'\x08\x00' or frame[23] != 17:
            continue
        header = (frame[14] & 15)*4
        udp = 14+header
        if struct.unpack_from('!HH',frame,udp) != (67,68):
            continue
        payload = udp+8
        if b'\x35\x01\x05' not in frame[payload+240:]:
            continue
        data[start+payload+19] ^= 1
        size = struct.unpack_from('!H',frame,udp+4)[0]
        struct.pack_into('!H',data,start+udp+6,0)
        pseudo = frame[26:34]+struct.pack('!BBH',0,17,size)
        segment = data[start+udp:start+udp+size]
        struct.pack_into('!H',data,start+udp+6,checksum(pseudo+segment) or 0xffff)
        require(not checksum(pseudo+data[start+udp:start+udp+size]), 'changed DHCP control has valid UDP checksum')
        return bytes(data)
    raise ValueError('actual normal capture lacks a DHCP ACK')


def captures(case, control, phases):
    for phase in phases:
        folder = control / phase['phase']
        folder.mkdir()
        for lane in (0,1):
            name = f'lane{lane}.pcap'
            shutil.copyfile(case / phase['phase'] / name,folder / name)


def verify(directory, output, selectors, baseline):
    output.mkdir(parents=True,exist_ok=False)
    (output / 'baseline.json').write_text(json.dumps(baseline,indent=2)+'\n')
    rows = json.loads((directory / 'results.json').read_text())
    row = rows[0]
    name = '-'.join(row[key] for key in ('provider','linkage','firmware','transport'))
    case = directory / name
    network = json.loads((case / 'network/network.json').read_text())
    phase = row['phases'][0]
    raw = (case / phase['phase'] / 'guest.log').read_bytes()
    originals = {path:fingerprint(path) for path in (case / phase['phase'] / 'guest.log',
        case / phase['phase'] / 'lane0.pcap',case / 'result.json',directory / 'source-inputs.json')}
    observed = []
    names = ('missing-guest-log','changed-tls-file-hash','guest-panic-with-success','wrong-firmware',
             'changed-tcp-checksum','changed-http-body-valid-checksum','truncated-capture',
             'changed-dhcp-valid-checksum','changed-native-dns-answer','changed-retained-source',
             'changed-producer-product','missing-profile')
    if selectors.get('storage','both') != 'ram':
        names += ('missing-persistent-export','changed-persistent-export')
    for label in names:
        control = output / label
        control.mkdir()
        phases = copy.deepcopy(row['phases'])
        if label in names[:4]:
            path = control / 'guest.log'
            if label != 'missing-guest-log':
                if label == 'changed-tls-file-hash':
                    changed = raw.replace(b'https.bin ddc5',b'https.bin eec5',1)
                elif label == 'guest-panic-with-success':
                    changed = raw+b'\nPANIC: actual normal-log control\n'
                else:
                    changed = raw.replace(b'Firmware: '+row['firmware'].upper().encode(),
                        b'Firmware: '+(b'UEFI' if row['firmware'] == 'bios' else b'BIOS'),1)
                require(changed != raw,'actual normal log changed')
                path.write_bytes(changed)
            check = lambda: guest(path.read_bytes(),phase['phase'] != 'reboot',phase['phase'] != 'ram',
                                  row['firmware'],row['curl_profiles'])
        elif label in names[4:9]:
            captures(case,control,phases)
            path = control / phase['phase'] / 'lane0.pcap'
            original = path.read_bytes()
            if label in ('changed-tcp-checksum','changed-http-body-valid-checksum'):
                path.write_bytes(damaged_capture(original,network['peers']['0']['http']['port'],
                    label == 'changed-http-body-valid-checksum'))
            elif label == 'truncated-capture':
                path.write_bytes(original[:-17])
            elif label == 'changed-dhcp-valid-checksum':
                path.write_bytes(changed_lease(original))
            else:
                network = copy.deepcopy(network)
                answer = bytearray.fromhex(network['queries'][0]['answer'])
                answer[-1] ^= 1
                network['queries'][0]['answer'] = answer.hex()
                (control / 'changed-network.json').write_text(json.dumps(network,indent=2)+'\n')
            phases[0]['captures']['lane0.pcap'] = fingerprint(path)
            check = lambda: wire(control,phases,network)
        elif label == 'changed-retained-source':
            shutil.copyfile(directory / 'source-inputs.json',control / 'source-inputs.json')
            shutil.copytree(directory / 'retained-source',control / 'retained-source')
            target = control / 'retained-source/scripts/http_download/normal_client.py'
            target.write_bytes(target.read_bytes()+b'\n# changed actual retained source\n')
            check = lambda: sources(control)
        elif label == 'changed-producer-product':
            for provider in ('build','runtime'):
                for package in ('curl','openssl','musl'):
                    filename = package+'-'+provider+'-manifest.json'
                    shutil.copyfile(directory / filename,control / filename)
            path = control / ('curl-'+row['provider']+'-manifest.json')
            manifest = json.loads(path.read_text())
            manifest['products'][row['linkage']+'/stage/usr/bin/curl'] = '0'*64
            path.write_text(json.dumps(manifest,indent=2)+'\n')
            check = lambda: products(control,case,row)
        elif label == 'missing-profile':
            for other in rows[1:]:
                (control / '-'.join(other[key] for key in ('provider','linkage','firmware','transport'))).mkdir()
            check = lambda: audit(control,control / 'audit',**selectors)
        else:
            for current in row['phases']:
                if current['phase'] != 'ram':
                    name = current['phase']+'-exports'
                    shutil.copytree(case / name,control / name,copy_function=os.link)
            actual = baseline['rows'][0]['final_disk']
            name = next(name for name in actual['files'] if name.startswith('/home/admin/downloads/'))
            target = control / 'create-exports' / (name.strip('/').replace('/','-')+'.bin')
            data = target.read_bytes()
            target.unlink()
            if label == 'changed-persistent-export':
                target.write_bytes(bytes((data[0]^1,))+data[1:])
            check = lambda: retained_exports(control,row['phases'],actual)
        try:
            check()
        except (ValueError,RuntimeError,FileNotFoundError,KeyError,struct.error) as error:
            rejection = dict(control=label,rejected=True,reason=str(error))
            (control / 'rejection.json').write_text(json.dumps(rejection,indent=2)+'\n')
            observed.append(rejection)
        else:
            raise RuntimeError('changed actual normal evidence was accepted: '+label)
    require(all(fingerprint(path) == value for path,value in originals.items()),
            'original normal evidence remains unchanged after damage controls')
    return dict(passed=True,controls=observed,original_actual_evidence_unchanged=True)

# SPDX-License-Identifier: GPL-3.0-or-later
"""Serialize invalid copies of real guest device packets and queries."""
from pathlib import Path
import re
import hashlib
import json
import tempfile
import zipfile
import shutil
import struct


def records(data):
    assert data[:4]==b'\xd4\xc3\xb2\xa1'
    at,result=24,[]
    while at<len(data):
        seconds,micros,length,original=struct.unpack_from('<IIII',data,at)
        assert length==original
        result.append(dict(offset=at,body=at+16,length=length,stamp=seconds*1000000+micros,
                           frame=bytearray(data[at+16:at+16+length])))
        at+=16+length
    assert at==len(data)
    return result


def checksum(data):
    data+=bytes(len(data)%2)
    value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535


def damage(case,target,variant):
    target.mkdir(parents=True)
    for name in ('lane0.pcap','lane1.pcap','serial.log','carrier.json'):
        source=case/name
        if source.exists():shutil.copyfile(source,target/name)
    buffers=[bytearray((target/f'lane{lane}.pcap').read_bytes()) for lane in range(2)]
    parsed=[records(data) for data in buffers]
    text=(target/'serial.log').read_text()
    def controls(kind,stage):
        return [(index,row) for index,row in enumerate(parsed[1]) if
                row['frame'][12:14]==b'\x88\xc4' and row['frame'][6:12]==bytes.fromhex('525400123411') and
                row['frame'][20]==kind and row['frame'][23]==stage]
    begin=controls(1,0)
    assert len(begin)==1
    probes=[(index,row) for index,row in enumerate(parsed[0]) if row['stamp']>begin[0][1]['stamp'] and
            row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]==58]
    assert probes
    physical=1
    if variant in ('nonce','checksum','missing-DAD','post-BEGIN-firmware'):
        physical=0
        if variant=='post-BEGIN-firmware':
            matches=[(index,row) for index,row in enumerate(parsed[0]) if
                     row['stamp']<begin[0][1]['stamp'] and row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]==0]
        else:matches=probes
    elif variant=='missing-ACK':
        matches=[(index,row) for index,row in enumerate(parsed[1]) if row['frame'][12:14]==b'\x88\xc4' and
                 row['frame'][6:12]==bytes.fromhex('024950360100') and row['frame'][19]==0]
    else:
        kind,stage={'subject':(0,0),'link-mtu':(6,2),'stable-key':(7,4),'ready-flags':(10,3),
                    'quiet-short':(6,2),'DAD-fast':(10,0),'DAD-subsecond':(10,0)}[variant]
        matches=controls(kind,stage)
    assert matches
    index,row=matches[0]
    frame=row['frame']
    data=buffers[physical]
    if variant in ('missing-ACK','missing-DAD'):
        del data[row['offset']:row['body']+row['length']]
    elif variant=='post-BEGIN-firmware':
        sec,micros=divmod(begin[0][1]['stamp']+100000,1000000)
        struct.pack_into('<II',data,row['offset'],sec,micros)
    else:
        if variant=='subject':frame[22]^=1
        elif variant=='link-mtu':struct.pack_into('!I',frame,28,1281)
        elif variant=='stable-key':frame[51]^=1
        elif variant=='ready-flags':struct.pack_into('!I',frame,24,0x840)
        elif variant=='checksum':frame[56]^=1
        elif variant=='nonce':
            frame[80:86]=bytes(6)
            frame[56:58]=bytes(2)
            struct.pack_into('!H',frame,56,checksum(frame[22:54]+struct.pack('!I3xB',32,58)+frame[54:]))
        elif variant in ('quiet-short','DAD-fast','DAD-subsecond'):
            interval=999900 if variant=='DAD-subsecond' else 100000
            delta=3500000 if variant=='quiet-short' else row['stamp']-(probes[0][1]['stamp']+interval)
            assert delta>0
            for value in (row,parsed[physical][index+1]):
                assert value['frame'][19]==frame[19]
                sec,micros=divmod(value['stamp']-delta,1000000)
                struct.pack_into('<II',data,value['offset'],sec,micros)
            stamp=int.from_bytes(frame[52:60],'big')-delta*1000
            assert stamp>0
            frame[52:60]=stamp.to_bytes(8,'big')
        data[row['body']:row['body']+row['length']]=frame
        if variant in ('link-mtu','stable-key','ready-flags','quiet-short','DAD-fast','DAD-subsecond'):
            phase=frame[19]
            matched=re.findall(r'^IPV6_DEVICE_CONTROL lane=1 phase='+str(phase)+r' .*?$',text,re.M)
            assert len(matched)==1
            replacement=matched[0]
            if variant=='link-mtu':replacement=re.sub(r'preferred=\d+','preferred=1281',replacement)
            elif variant=='stable-key':replacement=re.sub(r'target=[0-9a-f]{32}','target='+frame[36:52].hex(),replacement)
            elif variant=='ready-flags':replacement=re.sub(r'flags=[0-9a-f]+','flags=840',replacement)
            else:replacement=re.sub(r'observed_ns=\d+','observed_ns='+str(int.from_bytes(frame[52:60],'big')),replacement)
            text=text.replace(matched[0],replacement,1)
    (target/f'lane{physical}.pcap').write_bytes(data)
    (target/'serial.log').write_text(text)
    return dict(variant=variant,physical=physical,record=index)


GUEST_CONTROLS = ('subject', 'link-mtu', 'stable-key', 'ready-flags', 'nonce', 'checksum',
                  'missing-ACK', 'missing-DAD', 'quiet-short', 'DAD-fast', 'DAD-subsecond', 'post-BEGIN-firmware')


def controls(case, action, archive=None):
    from ipv6_device_capture import inspect
    case = Path(case)
    originals = {name: hashlib.sha256((case / name).read_bytes()).hexdigest()
                 for name in ('serial.log', 'lane0.pcap', 'lane1.pcap')}
    outcomes = []
    with tempfile.TemporaryDirectory(prefix='axiom64-ipv6-device-damage-') as temporary:
        root = Path(temporary)
        for variant in GUEST_CONTROLS:
            target = root / variant
            record = damage(case, target, variant)
            reason = None
            try:
                for lane in range(2):
                    inspect(target / f'lane{lane}.pcap', lane,
                            (target / 'serial.log').read_text(), action)
            except (ValueError, OSError) as failure:
                reason = str(failure)
            if reason is None:
                raise ValueError('serialized device damage was accepted: ' + variant)
            record.update(rejection=reason, inputs={path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                                    for path in target.iterdir()})
            (target / 'rejection.json').write_text(json.dumps(record, indent=2) + '\n')
            outcomes.append(record)
        if archive is not None:
            archive = Path(archive)
            with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as saved:
                for path in root.rglob('*'):
                    if path.is_file():
                        saved.write(path, path.relative_to(root).as_posix())
            reopened = root / 'reopened'
            reopened.mkdir()
            with zipfile.ZipFile(archive) as saved:
                if saved.testzip() is not None:
                    raise ValueError('serialized device damage ZIP CRC')
                for member in saved.namelist():
                    target = reopened / member
                    if not target.resolve().is_relative_to(reopened.resolve()):
                        raise ValueError('serialized device damage ZIP path')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(saved.read(member))
            for variant, record in zip(GUEST_CONTROLS, outcomes):
                target = reopened / variant
                if any(hashlib.sha256((target / name).read_bytes()).hexdigest() != digest
                       for name, digest in record['inputs'].items()):
                    raise ValueError('serialized device damage archive fingerprint')
                reason = None
                try:
                    for lane in range(2):
                        inspect(target / f'lane{lane}.pcap', lane,
                                (target / 'serial.log').read_text(), action)
                except (ValueError, OSError) as failure:
                    reason = str(failure)
                if reason != record['rejection']:
                    raise ValueError('serialized device damage archive lost its rejection')
    if any(hashlib.sha256((case / name).read_bytes()).hexdigest() != digest
           for name, digest in originals.items()):
        raise ValueError('original device evidence changed during damage checks')
    return outcomes

# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen changed original records, images and checksummed physical packets."""
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import zipfile
from ipv4_receive_wire_records import require
from ipv4_send_wire_capture import checksum, body


def record(data, name, case, field, change):
    lines=data.decode().splitlines(keepends=True)
    for at,line in enumerate(lines):
        if not line.startswith('IPV4_SEND_WIRE_'+name+' '):
            continue
        head,*fields=line.split()
        row=dict(item.split('=',1) for item in fields)
        if (int(row['lane']),int(row['case']))!=(0,case):
            continue
        row[field]=str(change(row[field]))
        lines[at]=head+' '+' '.join(key+'='+value for key,value in row.items())+('\r\n' if line.endswith('\r\n') else '\n')
        return ''.join(lines).encode()
    raise ValueError('actual negative-control record missing')


def frame_change(frame, case, phase, change):
    if len(frame)<51 or frame[12:14]!=b'\x08\0' or frame[42:46]!=b'SWIR' or frame[46:49]!=bytes((0,case,phase)) or frame[50]:
        return frame
    value=bytearray(frame)
    change(value)
    value[24:26]=bytes(2)
    struct.pack_into('!H',value,24,checksum(bytes(value[14:34])))
    if value[23]==17 and value[40:42]!=bytes(2):
        value[40:42]=bytes(2)
        segment=bytes(value[34:])
        pseudo=bytes(value[26:34])+struct.pack('!BBH',0,17,len(segment))
        struct.pack_into('!H',value,40,checksum(pseudo+segment) or 65535)
    return bytes(value)


def physical(directory, case, phase, change):
    original=(directory/'lane0.pcap').read_bytes()
    require(original[:4]==b'\xd4\xc3\xb2\xa1','original guest PCAP precision')
    altered=bytearray(original[:24]);at=24;changed=0
    while at<len(original):
        header=original[at:at+16];size=struct.unpack_from('<I',header,8)[0];at+=16
        frame=original[at:at+size];at+=size
        updated=frame_change(frame,case,phase,change)
        changed+=updated!=frame
        altered.extend(header+updated)
    require(changed==1,'one actual original selected packet')
    rows=json.loads((directory/'lane0-frames.json').read_bytes())
    changed=0
    for row in rows:
        frame=bytes.fromhex(row['data']);updated=frame_change(frame,case,phase,change)
        changed+=updated!=frame
        row['data']=updated.hex()
    require(changed==1,'same actual original transport packet')
    return {'lane0.pcap':bytes(altered),'lane0-frames.json':json.dumps(rows).encode()}


def lifetime_preferred_source(data):
    lines=data.decode().splitlines(keepends=True)
    for line_number,line in enumerate(lines):
        if not line.startswith('{'):
            continue
        row=json.loads(line)
        if (row.get('kind'),row.get('lane'),row.get('case'),row.get('phase'),row.get('routes')) != ('inventory',0,50,0,1):
            continue
        raw=bytearray.fromhex(row['hex']);at=0
        while at<len(raw):
            length,kind=struct.unpack_from('<IH',raw,at)
            if kind==24:
                fields={};position=at+28
                while position<at+length:
                    size,field=struct.unpack_from('<HH',raw,position)
                    fields[field]=(position+4,bytes(raw[position+4:position+size]))
                    position+=(size+3)&~3
                if fields.get(1,(0,b''))[1]==bytes.fromhex('c6120100') and 7 in fields:
                    raw[fields[7][0]+3]^=1
                    row['hex']=raw.hex()
                    lines[line_number]=json.dumps(row)+'\n'
                    return ''.join(lines).encode()
            at+=(length+3)&~3
    raise ValueError('actual lifetime preferred-source attribute missing')


def damaged(directory,destination):
    from ipv4_send_wire_contract import verify
    log=(directory/'client.log').read_bytes()
    controls=[
        ('connected-route-mtu',{'client.log':record(log,'OUTPUT',1,'mtu_after',lambda value:1401)}),
        ('ancillary-ttl',{'client.log':record(log,'OUTPUT',1,'control',lambda value:value[:32]+'26000000'+value[40:])}),
        ('sleeping-state',{'client.log':record(log,'SLEEP',36,'status',lambda value:bytes.fromhex(value).replace(b'S (sleeping)',b'R (running)').hex())}),
        ('sleeping-task-identity',{'client.log':record(log,'SLEEP',36,'tid',lambda value:int(value)+1)}),
        ('deferred-payload-fault',{'client.log':record(log,'WAIT',39,'error',lambda value:0)}),
        ('interrupted-request',{'client.log':record(log,'WAIT',41,'error',lambda value:11)}),
        ('missing-fill',{'client.log':record(log,'PRESSURE',36,'fills',lambda value:int(value)+1)}),
        ('raw-memory-refusal',{'client.log':record(log,'RAW_PRESSURE',42,'error',lambda value:11)}),
        ('raw-control-order',{'client.log':record(log,'RAW_ORDER',42,'error',lambda value:14)}),
        ('physical-selected-ttl',physical(directory,1,0,lambda value:value.__setitem__(22,38))),
        ('held-source',physical(directory,45,3,lambda value:value.__setitem__(slice(26,30),bytes.fromhex('0a4d0102')))),
        ('late-payload-byte',physical(directory,46,4,lambda value:value.__setitem__(-1,value[-1]^1))),
        ('retired-owner-output',physical(directory,36,2,lambda value:value.__setitem__(slice(42,None),body(0,36,3,0,0,1100)))),
        ('retired-window',{'client.log':record(log,'RETIRED_WINDOW',36,'finished_ns',lambda value:0)}),
        ('lifetime-connected-identity',{'client.log':record(log,'LIFETIME_INPUT',53,'connected',lambda value:0)}),
        ('lifetime-independent-fill',{'client.log':record(log,'LIFETIME_INPUT',50,'fill_index',lambda value:int(value)-1)}),
        ('lifetime-syscall-result',{'client.log':record(log,'LIFETIME',51,'result',lambda value:1099)}),
        ('lifetime-silent-error',{'client.log':record(log,'LIFETIME',52,'socket_error',lambda value:100)}),
        ('lifetime-retired-window',{'client.log':record(log,'LIFETIME_WINDOW',51,'finished_ns',lambda value:0)}),
        ('lifetime-actual-down',{'client.log':record(log,'LIFETIME_LINK',52,'down',lambda value:format(int(value,16)|1,'x'))}),
        ('lifetime-raw-preferred-source',{'client.log':lifetime_preferred_source(log)}),
        ('lifetime-held-prefix-source',physical(directory,56,3,lambda value:value.__setitem__(slice(26,30),bytes.fromhex('0a4d0102')))),
        ('lifetime-recreated-owner-output',physical(directory,51,1,lambda value:(value.__setitem__(22,37),value.__setitem__(15,184),value.__setitem__(slice(42,None),body(0,51,3,0,0,1100))))),
        ('lifetime-fallback-reselection',physical(directory,62,3,lambda value:value.__setitem__(slice(26,30),bytes.fromhex('0a4d0202')))),
    ]
    for label,name,change in (
        ('program','program.elf',lambda data:data[:-1]+bytes((data[-1]^1,))),
        ('kernel','kernel.elf',lambda data:data[:-1]+bytes((data[-1]^1,))),
        ('boot-image','image.iso',lambda data:data[:32768]+bytes(2048)+data[34816:]),
        ('source-archive','source.zip',lambda data:bytes((data[0]^1,))+data[1:]),
        ('compile-inputs','program.inputs.json',lambda data:json.dumps(dict(json.loads(data),sources={})).encode()),
        ('compile-threading','program.inputs.json',lambda data:json.dumps(dict(json.loads(data),command=[value for value in json.loads(data)['command'] if value!='-pthread'])).encode()),
        ('transport','results.json',lambda data:json.dumps(dict(json.loads(data),transport='legacy')).encode()),
        ('firmware','client.log',lambda data:data.replace(b'Firmware: BIOS',b'Firmware: UEFI'))):
        controls.append((label,{name:change((directory/name).read_bytes())}))
    with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED) as archive:
        for label,changes in controls:
            for name,changed in changes.items():
                require(changed!=(directory/name).read_bytes(),'changed actual negative-control input')
                archive.writestr(label+'/'+name,changed)
    rejected=[]
    with zipfile.ZipFile(destination) as archive:
        for label,changes in controls:
            with tempfile.TemporaryDirectory(prefix='axiom-send-wire-control-') as temporary:
                scratch=Path(temporary)/'case'
                def copy(source,target):
                    try:
                        os.link(source,target)
                    except OSError:
                        shutil.copy2(source,target)
                    return target
                shutil.copytree(directory,scratch,copy_function=copy)
                for name in changes:
                    target=scratch/name
                    target.unlink()
                    target.write_bytes(archive.read(label+'/'+name))
                try:
                    verify(scratch)
                except (ValueError,KeyError,IndexError,TypeError,struct.error,zipfile.BadZipFile):
                    rejected.append(label)
                else:
                    raise ValueError('changed actual evidence accepted: '+label)
    return rejected


def native_damaged(directory,destination):
    from ipv4_send_wire_contract import verify
    original=json.loads((directory/'native-configuration.json').read_text())
    controls=[]
    for label in ('peer-namespace-reuse','peer-index-pair','checksum-offload','peer-administration','peer-address','peer-ipv6'):
        value=json.loads(json.dumps(original));links=value['stable_peer_links']
        if label=='peer-namespace-reuse':
            links['peer_namespace_inode']=value['namespace_inode']
        elif label=='peer-index-pair':
            links['interfaces'][1]['link_index']+=1
        elif label=='checksum-offload':
            links['features'][0]['after']=links['features'][0]['after'].replace('tx-checksumming: off','tx-checksumming: on')
        elif label=='peer-administration':
            links['interfaces'][1]['flags'].remove('UP')
        elif label=='peer-address':
            links['addresses'].append(dict(ifname='peer0',addr_info=[dict(local='10.77.1.2')]))
        else:
            links['peer_sysctls'][0]['configured']='0\n'
        controls.append((label,json.dumps(value).encode()))
    with zipfile.ZipFile(destination,'x',zipfile.ZIP_DEFLATED) as archive:
        for label,encoded in controls:
            require(encoded!=(directory/'native-configuration.json').read_bytes(),'changed actual native peer evidence')
            archive.writestr(label+'/native-configuration.json',encoded)
    rejected=[]
    with zipfile.ZipFile(destination) as archive:
        for label,_ in controls:
            with tempfile.TemporaryDirectory(prefix='axiom-send-native-control-') as temporary:
                scratch=Path(temporary)/'case'
                def copy(source,target):
                    try:os.link(source,target)
                    except OSError:shutil.copy2(source,target)
                    return target
                shutil.copytree(directory,scratch,copy_function=copy)
                selected=scratch/'native-configuration.json';selected.unlink()
                selected.write_bytes(archive.read(label+'/native-configuration.json'))
                try:verify(scratch)
                except (ValueError,KeyError,IndexError,TypeError,struct.error,zipfile.BadZipFile):rejected.append(label)
                else:raise ValueError('changed native peer evidence accepted: '+label)
    return rejected

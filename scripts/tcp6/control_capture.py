# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently verify TCP control scalars, router changes and physical headers."""
import ipaddress
import hashlib
import json
import re
import struct
import tempfile
import zipfile
from copy import deepcopy
from pathlib import Path
from ipv4_expiry_capture import read_capture, encode_capture
from tcp6.capture import require
from tcp6.observation import bind
from tcp6.peer import packet as packet6
from tcp_fault_peer import ACK,FIN,SYN,checksum,packet as packet4

POINTS=[('fresh',64,168,44),('connected',41,168,44),('class-cleared',64,24,44),('class-sent',41,24,44),
    ('tos-cleared',64,24,108),('tos-sent',41,24,108),('zero-hop',0,24,108),('explicit-hop',37,24,108),
    ('router-changed-explicit',37,24,108),('default-restored',51,24,108),('same-class',51,24,108),
    ('same-tos',51,24,108),('device-cleared',64,24,108),('device-reselected',51,24,108),
    ('device-bound',64,24,108),('closing',37,168,108)]

def verify(path,lane,log,native=False,statistics=None,*,family):
    require(family in ('ipv6','mapped','ipv4'),'known captured family')
    marker=f'TCP_CONTROL_FAMILY_PASS family={family} lanes=2 exchanges_each=11 router_hops=41,51 detached_reply=1'
    require(log.splitlines().count(marker)==1,'complete actual family application')
    points=[(f,int(n),phase,int(h),int(c),int(t),int(s)) for f,n,phase,h,c,t,s in re.findall(
        r'^TCP_CONTROL_FAMILY_POINT family=(ipv6|mapped|ipv4) lane=(\d+) phase=([a-z-]+) hops=(-?\d+) class=(-?\d+) ttl=(\d+) tos=(\d+)\r?$',log,re.M)]
    require(points==[(family,n,phase,-2 if family=='ipv4' else h,-2 if family=='ipv4' else c,77,s)
        for n in range(2) for phase,h,c,s in POINTS],'complete native-derived family scalar snapshots')
    phases=[tuple(map(int,values)) for values in re.findall(r'^TCP_CONTROL_FAMILY_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M)]
    require(phases==[(0,0),(1,0),(0,1),(0,2),(0,3),(1,1),(1,2),(1,3)],'complete actual family application barriers')
    rows=read_capture(path)
    clock=bind(path,rows,statistics) if native else None
    local=ipaddress.IPv6Address(f'2001:db8:{lane+1}::2').packed if family=='ipv6' else bytes([10,23,lane+1,2])
    remote=ipaddress.IPv6Address(f'2001:db8:{lane+1}::1').packed if family=='ipv6' else bytes([10,23,lane+1,1])
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane])
    peer=bytes([2,0x41,0x58,0x54,0x43,lane])
    control=bytes([2,73,80,54,lane,0])
    data=[];routers=[];syn=[];fin=[];incoming_fin=[];late=[];barriers={}
    sent=[];echoes=[];synacks=[];sent_fin=[];received_fin=[];detached=[]
    for at,row in enumerate(rows):
        frame=row['frame']
        if len(frame)>=21 and frame[12:14]==b'\x88\xc8':
            phase,answer=frame[19:21]
            require(len(frame)==60 and phase in (0,1,2,3) and answer in (0,1) and (phase,answer) not in barriers,
                'unique original family barriers')
            require(frame[:12]==(guest+control if answer else control+guest) and frame[14:19]==b'IP6F'+bytes([lane]) and
                not any(frame[21:]),'original actual family barrier ownership')
            barriers[phase,answer]=at
        v6=len(frame)>=54 and frame[12:14]==b'\x86\xdd'
        if v6:
            ip=frame[14:];length=int.from_bytes(ip[4:6],'big')
            require(ip[0]>>4==6 and length<=len(ip)-40,'original family IPv6 bounds')
            if ip[6]==58:
                require(length>=8 and not checksum(ip[8:40]+struct.pack('!I3xB',length,58)+ip[40:40+length]),'original family ICMPv6 checksum')
                if ip[40]==134:
                    require(ip[7]==255 and ip[8:24]==ipaddress.IPv6Address('fe80::1').packed and ip[24:40]==ipaddress.IPv6Address('fe80::2').packed,
                        'original family RA addresses and hops')
                    routers.append((at,ip[44]))
            if ip[6]!=6:continue
        elif not (len(frame)>=54 and frame[12:14]==b'\x08\0' and frame[23]==6):continue
        require(v6==(family=='ipv6'),'original actual socket wire family')
        value=packet6(frame) if v6 else packet4(frame)
        outgoing=value['source_ip']==local
        require(value['source_ip']+value['target_ip']==(local+remote if outgoing else remote+local) and
            (value['source'],value['target'])==((49880+lane,49890+lane) if outgoing else (49890+lane,49880+lane)),
            'original actual family complete tuple')
        require(frame[:12]==(peer+guest if outgoing else guest+peer),'original actual family TCP Ethernet ownership')
        header=(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255) if v6 else (frame[22],frame[15])
        if outgoing:
            if value['flags']==SYN:
                syn.append((at,header))
                opening=value
            if value['data']:
                tag=len(data)
                require(tag<11,'bounded original family payload inventory')
                expected=([(41,168),(41,24),(41,24),(0,24),(37,24),(37,24),(51,24),(51,24),(51,24),(51,24),(51,24)][tag]
                    if v6 else (77,44 if tag<2 else 108))
                require(tag<11 and value['data']==bytes((tag*17+lane*53+n*7)&255 for n in range(16)) and header==expected,
                    'all original family live payload and header controls')
                data.append((at,tag))
                sent.append((at,value))
            if value['flags']&FIN:
                fin.append((at,header))
                sent_fin.append(value)
            if len(incoming_fin)==2 and not value['data'] and value['flags']==ACK:
                late.append((at,header))
                detached.append(value)
        else:
            if value['flags']==SYN|ACK:synacks.append((at,value))
            if value['data']:echoes.append((at,value))
            if value['flags']&FIN:
                incoming_fin.append((at,frame))
                received_fin.append(value)
    require(set(barriers)=={(p,a) for p in range(4) for a in range(2)},'all original family barriers')
    require([h for _,h in routers]==[41,51] and len(syn)==1 and syn[0][1]==((41,168) if family=='ipv6' else (77,44)) and len(data)==11,
        'both original RAs and complete family stream')
    require(barriers[1,0]<routers[0][0]<barriers[1,1]<syn[0][0]<data[0][0] and data[4][0]<barriers[2,0]<routers[1][0]<barriers[2,1]<data[5][0],
        'original family ordering binds router changes')
    expected=(51,168) if family=='ipv6' else (64,168 if family=='mapped' else 108)
    require(len(fin)==1 and fin[0][1]==((37,168) if family=='ipv6' else (77,108)) and len(incoming_fin)==2 and incoming_fin[0][1]==incoming_fin[1][1] and
        len(late)==1 and late[0][1]==expected and data[-1][0]<fin[0][0]<incoming_fin[0][0]<barriers[3,0]<incoming_fin[1][0]<late[0][0]<barriers[3,1],
        'original detached family reply uses native-derived default hops and retained class')
    require(len(synacks)==1 and len(echoes)==11 and syn[0][0]<synacks[0][0]<data[0][0] and
            synacks[0][1]['ack']==(opening['seq']+1)&0xffffffff,
            'actual complete TCP handshake and returned stream')
    client=(opening['seq']+1)&0xffffffff
    server=(synacks[0][1]['seq']+1)&0xffffffff
    for tag,((sent_at,request),(echo_at,response)) in enumerate(zip(sent,echoes)):
        require(sent_at<echo_at and (tag==10 or echo_at<sent[tag+1][0]) and
                request['seq']==(client+tag*16)&0xffffffff and request['ack']==(server+tag*16)&0xffffffff and
                response['seq']==(server+tag*16)&0xffffffff and response['ack']==(client+(tag+1)*16)&0xffffffff and
                response['data']==request['data'], 'actual ordered TCP request and echo bytes')
    require(len(sent_fin)==1 and len(detached)==1 and
            sent_fin[0]['seq']==(client+176)&0xffffffff and sent_fin[0]['ack']==(server+176)&0xffffffff and
            all(value['seq']==(server+176)&0xffffffff and value['ack']==(client+177)&0xffffffff for value in received_fin) and
            detached[0]['seq']==(client+177)&0xffffffff and detached[0]['ack']==(server+177)&0xffffffff,
            'actual TCP closure sequence survives final descriptor release')
    return dict(passed=True,family=family,lane=lane,frames=len(rows),exchanges=11,scalar_snapshots=32,
        original_router_hops=[41,51],detached_reply_header=expected,clock=clock,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def damaged(path,lane,log,native,output,statistics=None,*,family):
    verify(path,lane,log,native,statistics,family=family)
    original=path.read_bytes()
    rows=read_capture(path)
    outgoing=[];incoming_fin=[];routers=[];barriers=[];echoes=[]
    for index,row in enumerate(rows):
        frame=row['frame']
        if len(frame)>=21 and frame[12:14]==b'\x88\xc8' and frame[19:21]==b'\3\1':barriers.append(index)
        if len(frame)>=78 and frame[12:14]==b'\x86\xdd' and frame[20]==58 and frame[54]==134:routers.append(index)
        if len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6:value=packet6(frame)
        elif len(frame)>=54 and frame[12:14]==b'\x08\0' and frame[23]==6:value=packet4(frame)
        else:continue
        if value['source']==49880+lane:outgoing.append((index,value))
        else:
            if value['flags']&FIN:incoming_fin.append(index)
            if value['data']:echoes.append(index)
    syn=next(i for i,v in outgoing if v['flags']==SYN)
    data=[i for i,v in outgoing if v['data']]
    fin=next(i for i,v in outgoing if v['flags']&FIN)
    late=next(i for i,v in outgoing if i>incoming_fin[-1] and v['flags']==ACK)
    cases=[('syn-hop',syn,'hop'),('syn-class',syn,'class'),('data-hop',data[0],'hop'),('data-class',data[0],'class'),
        ('fourth-send-hop',data[3],'hop'),('fin-hop',fin,'hop'),('fin-class',fin,'class'),
        ('detached-hop',late,'hop'),('detached-class',late,'class'),('router-first',routers[0],'router'),
        ('router-second',routers[1],'router'),('scalar',None,'scalar'),('tcp-owner',syn,'owner'),
        ('barrier-owner',barriers[0],'owner'),('echo-payload',echoes[0],'payload'),
        ('echo-sequence',echoes[0],'sequence'),('missing-completion',None,'completion')]
    archive_path=output/(path.stem+'-damaged.zip')
    controls=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        for label,index,field in cases:
            changed=deepcopy(rows);text=log
            if field=='scalar':
                text=re.sub(r'ttl=77','ttl=76',log,count=1) if family=='ipv4' else re.sub(r'hops=64','hops=65',log,count=1)
            elif field=='completion':
                text=re.sub(r'^TCP_CONTROL_FAMILY_PASS .*\r?\n','',log,count=1,flags=re.M)
            else:
                frame=bytearray(changed[index]['frame'])
                if field=='owner':frame[11]^=1
                elif field=='router':
                    frame[58]^=1
                    size=int.from_bytes(frame[18:20],'big');frame[56:58]=bytes(2)
                    frame[56:58]=struct.pack('!H',checksum(frame[22:54]+struct.pack('!I3xB',size,58)+frame[54:54+size]))
                elif field in ('payload','sequence'):
                    start=54 if family=='ipv6' else 14+(frame[14]&15)*4
                    frame[start+((frame[start+12]>>4)*4 if field=='payload' else 4)]^=1
                    frame[start+16:start+18]=bytes(2)
                    segment=frame[start:54+int.from_bytes(frame[18:20],'big')] if family=='ipv6' else frame[start:14+int.from_bytes(frame[16:18],'big')]
                    pseudo=(frame[22:54]+struct.pack('!I3xB',len(segment),6) if family=='ipv6' else
                            frame[26:34]+struct.pack('!BBH',0,6,len(segment)))
                    frame[start+16:start+18]=struct.pack('!H',checksum(pseudo+segment))
                elif family=='ipv6':
                    if field=='hop':frame[21]^=1
                    else:frame[14:18]=(int.from_bytes(frame[14:18],'big')^(1<<20)).to_bytes(4,'big')
                else:
                    frame[22 if field=='hop' else 15]^=1
                    size=(frame[14]&15)*4;frame[24:26]=bytes(2)
                    frame[24:26]=struct.pack('!H',checksum(frame[14:14+size]))
                changed[index]['frame']=bytes(frame)
            context=dict(family=family,lane=lane,native=native,changed_field=field,changed_frame=index)
            body=encode_capture(changed)
            payloads={'lane.pcap':body,'client.log':text.encode()}
            context.update(capture_sha256=hashlib.sha256(body).hexdigest(),log_sha256=hashlib.sha256(text.encode()).hexdigest())
            if native:
                clocks=[json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()]
                if index is not None:clocks[index]['sha256']=hashlib.sha256(changed[index]['frame']).hexdigest()
                encoded=('\n'.join(json.dumps(row) for row in clocks)+'\n').encode()
                stats=deepcopy(statistics)
                stats.update(monotonic_receipts='lane.clocks.jsonl',monotonic_receipts_sha256=hashlib.sha256(encoded).hexdigest())
                context['statistics']=stats
                payloads['lane.clocks.jsonl']=encoded
            payloads['context.json']=json.dumps(context).encode()
            for name,body in payloads.items():archive.writestr(label+'/'+name,body)
            controls.append(dict(name=label,files=list(payloads)))
    rejected=[]
    with zipfile.ZipFile(archive_path) as archive:
        for control in controls:
            with tempfile.TemporaryDirectory(prefix='tcp-control-damage-') as temporary:
                case=Path(temporary)
                for name in control['files']:(case/name).write_bytes(archive.read(control['name']+'/'+name))
                context=json.loads((case/'context.json').read_text())
                require(hashlib.sha256((case/'lane.pcap').read_bytes()).hexdigest()==context['capture_sha256'] and
                        hashlib.sha256((case/'client.log').read_bytes()).hexdigest()==context['log_sha256'],
                        'reopened altered family evidence bytes')
                try:verify(case/'lane.pcap',lane,(case/'client.log').read_text(),native,context.get('statistics'),family=family)
                except ValueError as error:
                    require(not any(term in str(error) for term in ('checksum','arrival','clock','fingerprint')),
                            'changed family evidence reaches semantic rejection')
                    rejected.append(dict(name=control['name'],reason=str(error)))
                else:raise ValueError('reopened damaged TCP control evidence passed: '+control['name'])
    require(len(rejected)==17 and path.read_bytes()==original,'all TCP control mutations rejected and original unchanged')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

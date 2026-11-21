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

PASSIVE_PHASES=('listener-initial','listener-pending-update','accepted-pending',
    'accepted-after-listener-update','accepted-second','first-default-after-listener-close',
    'second-after-listener-close','second-after-first-detached')


def _reconstruct(path,lane,log,native=False,statistics=None,*,family):
    require(family in ('ipv6','mapped','ipv4'),'known observed passive family')
    marker=f'TCP_CONTROL_FAMILY_PASS family={family} lanes=2 exchanges_each=16 router_hops=41,51 detached_replies=3 passive_flows_each=2 pending_retry=1 listener_closed=1'
    require(log.splitlines().count(marker)==1,'original passive application completes')
    active=[(f,int(n),phase,int(h),int(c),int(t),int(s)) for f,n,phase,h,c,t,s in re.findall(
        r'^TCP_CONTROL_FAMILY_POINT family=(ipv6|mapped|ipv4) lane=(\d+) phase=([a-z-]+) hops=(-?\d+) class=(-?\d+) ttl=(\d+) tos=(\d+)\r?$',log,re.M)]
    require(active==[(family,n,phase,-2 if family=='ipv4' else h,-2 if family=='ipv4' else c,77,s)
        for n in range(2) for phase,h,c,s in POINTS],'all preceding active scalar controls remain')
    points=[(f,int(n),phase,int(h),int(c),int(t),int(s),int(v),b) for f,n,phase,h,c,t,s,v,b in re.findall(
        r'^TCP_CONTROL_PASSIVE_POINT family=(ipv6|mapped|ipv4) lane=(\d+) phase=([a-z-]+) hops=(-?\d+) class=(-?\d+) ttl=(\d+) tos=(\d+) v6only=(-?\d+) binding=(eth\d+)\r?$',log,re.M)]
    require([(f,n,p,b) for f,n,p,_,_,_,_,_,b in points]==[(family,n,p,f'eth{n}') for n in range(2) for p in PASSIVE_PHASES],
        'complete observed passive scalar/device points')
    phases=[tuple(map(int,values)) for values in re.findall(r'^TCP_CONTROL_FAMILY_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M)]
    require(phases==[(0,0),(1,0)]+[(n,p) for n in range(2) for p in range(1,9)],'all actual passive application barriers')
    rows=read_capture(path)
    clock=bind(path,rows,statistics) if native else None
    local=ipaddress.IPv6Address(f'2001:db8:{lane+1}::2').packed if family=='ipv6' else bytes([10,23,lane+1,2])
    remote=ipaddress.IPv6Address(f'2001:db8:{lane+1}::1').packed if family=='ipv6' else bytes([10,23,lane+1,1])
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane]);peer=bytes([2,0x41,0x58,0x54,0x43,lane])
    control=bytes([2,73,80,54,lane,0])
    barriers={};routers=[]
    definitions={'active':(49880+lane,49890+lane,list(range(11))),
                 'pending':(49910+lane,49920+lane,[20,21,22]),
                 'second':(49910+lane,49930+lane,[30,31])}
    streams={name:[] for name in definitions}
    for index,row in enumerate(rows):
        frame=row['frame']
        if len(frame)>=21 and frame[12:14]==b'\x88\xc8':
            phase,answer=frame[19:21]
            require(len(frame)==60 and phase in range(9) and answer in (0,1) and (phase,answer) not in barriers and
                frame[:12]==(guest+control if answer else control+guest) and frame[14:19]==b'IP6F'+bytes([lane]) and not any(frame[21:]),
                'original unique passive Ethernet barriers')
            barriers[phase,answer]=index
        v6=len(frame)>=54 and frame[12:14]==b'\x86\xdd'
        if v6:
            ip=frame[14:];length=int.from_bytes(ip[4:6],'big')
            require(ip[0]>>4==6 and length<=len(ip)-40,'original passive IPv6 bounds')
            if ip[6]==58:
                require(length>=8 and not checksum(ip[8:40]+struct.pack('!I3xB',length,58)+ip[40:40+length]),'original passive ICMPv6 checksum')
                if ip[40]==134:
                    require(ip[7]==255 and ip[8:24]==ipaddress.IPv6Address('fe80::1').packed and
                        ip[24:40]==ipaddress.IPv6Address('fe80::2').packed,'original passive router addresses')
                    routers.append((index,ip[44]))
            if ip[6]!=6:continue
        elif not (len(frame)>=54 and frame[12:14]==b'\x08\0' and frame[23]==6):continue
        require(v6==(family=='ipv6'),'original passive actual wire family')
        value=packet6(frame) if v6 else packet4(frame)
        outgoing=value['source_ip']==local
        require(value['source_ip']+value['target_ip']==(local+remote if outgoing else remote+local) and
            frame[:12]==(peer+guest if outgoing else guest+peer) and not value['flags']&4,'original passive addresses, Ethernet owner and no reset')
        matches=[name for name,(a,b,_) in definitions.items() if (value['source'],value['target'])==((a,b) if outgoing else (b,a))]
        require(len(matches)==1,'every original TCP packet belongs to one complete flow')
        header=(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255) if v6 else (frame[22],frame[15])
        streams[matches[0]].append(dict(index=index,value=value,outgoing=outgoing,header=header,frame=frame))
    require(set(barriers)=={(p,a) for p in range(9) for a in range(2)} and [h for _,h in routers]==[41,51],
        'all original active/passive barriers and two routers')
    observations={}
    for name,packets in streams.items():
        passive=name!='active';tags=definitions[name][2]
        syn=[item for item in packets if item['value']['flags']==SYN]
        synack=[item for item in packets if item['value']['flags']==SYN|ACK]
        data=[item for item in packets if item['outgoing'] and item['value']['data']]
        echo=[item for item in packets if not item['outgoing'] and item['value']['data']]
        fin=[item for item in packets if item['outgoing'] and item['value']['flags']&FIN]
        peer_fin=[item for item in packets if not item['outgoing'] and item['value']['flags']&FIN]
        require(len(syn)==1 and syn[0]['outgoing']!=passive and len(synack)==(2 if name=='pending' else 1) and
            all(item['outgoing']==passive for item in synack),'actual original handshake direction and retry count')
        local_base=((synack[0] if passive else syn[0])['value']['seq']+1)&0xffffffff
        remote_base=((syn[0] if passive else synack[0])['value']['seq']+1)&0xffffffff
        require(all(item['value']['seq']==((local_base if passive else remote_base)-1)&0xffffffff and
            item['value']['ack']==(remote_base if passive else local_base) for item in synack),'actual SYN-ACK sequences and original retry identity')
        require(len(data)==len(echo)==len(tags) and len(fin)==1 and len(peer_fin)==2 and
            peer_fin[0]['frame']==peer_fin[1]['frame'],'complete actual streams and identical duplicate FIN')
        require(syn[0]['index']<synack[0]['index']<data[0]['index'],
                'original handshake completes before actual application data')
        for n,(request,response) in enumerate(zip(data,echo)):
            a,b=request['value'],response['value']
            expected=bytes((tags[n]*17+lane*53+k*7)&255 for k in range(16))
            require(a['data']==b['data']==expected and a['seq']==(local_base+n*16)&0xffffffff and
                a['ack']==(remote_base+n*16)&0xffffffff and b['seq']==(remote_base+n*16)&0xffffffff and
                b['ack']==(local_base+(n+1)*16)&0xffffffff and request['index']<response['index'] and
                (n==len(tags)-1 or response['index']<data[n+1]['index']),'original exact request/echo bytes and complete stream sequence')
        count=16*len(tags)
        require(fin[0]['value']['seq']==(local_base+count)&0xffffffff and fin[0]['value']['ack']==(remote_base+count)&0xffffffff and
            all(item['value']['seq']==(remote_base+count)&0xffffffff and item['value']['ack']==(local_base+count+1)&0xffffffff for item in peer_fin),
            'actual complete passive close sequence')
        late=[item for item in packets if item['index']>peer_fin[1]['index'] and item['outgoing'] and item['value']['flags']==ACK and not item['value']['data']]
        require(len(late)==1 and late[0]['value']['seq']==(local_base+count+1)&0xffffffff and
            late[0]['value']['ack']==(remote_base+count+1)&0xffffffff,'actual detached reply sequence and acknowledgment')
        closing_phase={'active':3,'pending':7,'second':8}[name]
        require(data[-1]['index']<fin[0]['index']<peer_fin[0]['index']<barriers[closing_phase,0]<peer_fin[1]['index']<
            late[0]['index']<barriers[closing_phase,1],'application final close barrier precedes original duplicate FIN and detached ACK')
        observations[name]=dict(syn_header=syn[0]['header'],syn=syn[0]['index'],synack=[item['index'] for item in synack],
            data=[item['index'] for item in data],fin=fin[0]['index'],late=late[0]['index'],
            synack_headers=[item['header'] for item in synack],data_headers=[item['header'] for item in data],
            fin_header=fin[0]['header'],detached_header=late[0]['header'])
    a,b,c=(observations[name] for name in ('active','pending','second'))
    require(barriers[1,0]<routers[0][0]<barriers[1,1]<a['syn']<a['data'][0] and
        a['data'][4]<barriers[2,0]<routers[1][0]<barriers[2,1]<a['data'][5], 'original active router/data causality')
    require(barriers[4,0]<b['syn']<b['synack'][0]<barriers[4,1]<barriers[5,0]<b['synack'][1]<barriers[5,1]<b['data'][0] and
        b['data'][1]<barriers[6,0]<c['syn']<c['synack'][0]<barriers[6,1]<b['data'][2]<c['data'][0] and
        c['data'][0]<barriers[7,0]<barriers[7,1]<c['data'][1]<barriers[8,0], 'original pending listener update and independent accepted-child generations')
    first,second=(rows[index] for index in b['synack'])
    minimum=second.get('arrival_lower_ns',second['ns'])-first.get('arrival_upper_ns',first['ns'])
    return dict(passed=True,
        family=family,lane=lane,frames=len(rows),actual_exchanges=16,actual_flows=3,
        passive_points=[item for item in points if item[1]==lane],observed_headers=observations,
        original_pending_retry_lower_bound_ns=minimum,clock=clock,sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def verify(path, lane, log, native=False, statistics=None, *, family):
    result = _reconstruct(path, lane, log, native, statistics, family=family)
    v6 = family != 'ipv4'
    only = 1 if family == 'ipv6' else 0 if v6 else -2
    values = (
        ('listener-initial', 37, 168, 77, 44),
        ('listener-pending-update', 55, 204, 79, 100),
        ('accepted-pending', 55, 204, 79, 100),
        ('accepted-after-listener-update', 55, 204, 79, 100),
        ('accepted-second', 63, 232, 83, 116),
        ('first-default-after-listener-close', 51, 204, 79, 100),
        ('second-after-listener-close', 63, 232, 83, 116),
        ('second-after-first-detached', 63, 232, 83, 116),
    )
    expected = [(family, lane, phase, h if v6 else -2, c if v6 else -2,
                 ttl, tos, only, f'eth{lane}') for phase, h, c, ttl, tos in values]
    require(result['passive_points'] == expected,
            'listener update at final ACK, accepted-child independence and inherited controls')
    active = result['observed_headers']['active']
    require(active['syn_header'] == ((41, 168) if family == 'ipv6' else (77, 44)),
            'original active SYN header controls')
    require(active['data_headers'] == ([(41, 168), (41, 24), (41, 24), (0, 24),
             (37, 24), (37, 24)] + [(51, 24)] * 5 if family == 'ipv6' else
             [(77, 44)] * 2 + [(77, 108)] * 9), 'all original active wire controls')
    require(active['fin_header'] == ((37, 168) if family == 'ipv6' else (77, 108)) and
            active['detached_header'] == ((51, 168) if family == 'ipv6' else
             (64, 168 if family == 'mapped' else 108)), 'original active close and detached controls')
    pending = result['observed_headers']['pending']
    second = result['observed_headers']['second']
    require(pending['synack_headers'] == ([(37, 168), (55, 204)] if family == 'ipv6' else
             [(77, 44), (79, 100)]), 'pending SYN-ACK retry uses live listener controls')
    require(pending['data_headers'] == ([(55, 204)] * 2 + [(51, 204)] if family == 'ipv6' else
             [(79, 100)] * 3), 'first accepted child retains its final-ACK generation')
    require(pending['fin_header'] == ((51, 204) if family == 'ipv6' else (79, 100)) and
            pending['detached_header'] == ((51, 204) if family == 'ipv6' else
             (64, 204 if family == 'mapped' else 100)), 'first child closes after listener release')
    header = (63, 232) if family == 'ipv6' else (83, 116)
    require(second['synack_headers'] == [header] and second['data_headers'] == [header] * 2 and
            second['fin_header'] == header and second['detached_header'] ==
            ((51, 232) if family == 'ipv6' else (64, 232 if family == 'mapped' else 116)),
            'second generation survives final listener close and first child detachment')
    # Preserve the physical loss reader's handshake observation threshold.
    # The engine retains its one-second timer and ten-millisecond clock ticks.
    require(result['original_pending_retry_lower_bound_ns'] >= 850_000_000,
            'actual original handshake retry observation is at least 850 milliseconds')
    result.update(exchanges=16,scalar_snapshots=48,original_router_hops=[41,51],
                  detached_replies=3,passive_flows=2,listener_closed=True)
    return result


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
        elif value['source']==49890+lane:
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
    selected={}
    for index,row in enumerate(rows):
        frame=row['frame']
        if len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6:value=packet6(frame)
        elif len(frame)>=54 and frame[12:14]==b'\x08\0' and frame[23]==6:value=packet4(frame)
        else:continue
        if value['source']==49910+lane:
            selected.setdefault(value['target'],[]).append((index,value))
    for port,packets in selected.items():
        slot=port-(49920+lane)
        acknowledgments=[index for index,value in packets if value['flags']==SYN|ACK]
        transfers=[index for index,value in packets if value['data']]
        closing=next(index for index,value in packets if value['flags']&FIN)
        detached=packets[-1][0]
        for name,indexes in (('synack',acknowledgments),('data',transfers),('fin',[closing]),('detached',[detached])):
            for number,index in enumerate(indexes):
                for field in ('hop','class'):
                    cases.append((f'passive-{slot}-{name}-{number}-{field}',index,field))
    for phase in PASSIVE_PHASES:
        for field in ('ttl','tos','hops','class','v6only','binding'):
            cases.append((f'passive-point-{phase}-{field}',None,'passive-scalar:'+phase+':'+field))
    cases.append(('missing-passive-barrier',None,'passive-phase'))
    archive_path=output/(path.stem+'-damaged.zip')
    controls=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        for label,index,field in cases:
            changed=deepcopy(rows);text=log
            if field.startswith('passive-scalar:'):
                _,phase,selected=field.split(':')
                pattern=rf'^(TCP_CONTROL_PASSIVE_POINT family={family} lane={lane} phase={phase} .*?{selected}=)([^ \r\n]+)'
                def change(match):
                    value=match[2]
                    return match[1]+('eth9' if selected=='binding' else str(int(value)+1))
                text,count=re.subn(pattern,change,log,count=1,flags=re.M)
                require(count==1,'selected actual passive scalar record exists')
            elif field=='passive-phase':
                text,count=re.subn(rf'^TCP_CONTROL_FAMILY_PHASE_PASS lane={lane} phase=8\r?\n','',log,count=1,flags=re.M)
                require(count==1,'actual passive close barrier exists')
            elif field=='scalar':
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
    require(len(rejected)==len(cases)==90 and path.read_bytes()==original,'all TCP control mutations rejected and original unchanged')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

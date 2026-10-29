# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen retained-source flows independently of the live peer state machine."""
import hashlib
import json
from pathlib import Path
from copy import deepcopy
import struct
import tempfile
import zipfile
import ipaddress
import re
from ipv4_expiry_capture import read_capture,encode_capture
from tcp6.capture import require
from tcp6.observation import bind
from tcp6.peer import packet
from tcp_fault_peer import ACK,FIN,SYN,checksum

MARKER='TCP6_SOURCE_LIFETIME_PASS lanes=2 rounds_each=2 flows_each=4 data_each=12 withdrawn_each=6'

def _reconstruct(path,lane,log,native=False,statistics=None):
    require(log.splitlines().count(MARKER)==1,'actual source-lifetime application completion')
    phases=[tuple(map(int,row)) for row in re.findall(r'^TCP6_SOURCE_LIFETIME_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M)]
    require(phases==[(0,0),(1,0)]+[(n,r*16+s) for n in range(2) for r in range(2) for s in range(1,8)],'all actual source-lifetime phases')
    points=[(int(n),int(r),phase,int(h),int(c),int(e),device,int(cap)) for n,r,phase,h,c,e,device,cap in re.findall(
        r'^TCP6_SOURCE_POINT lane=(\d+) round=(\d+) phase=([a-z-]+) hops=(-?\d+) class=(\d+) error=(\d+) binding=([a-z0-9-]+) capacity=(\d+)\r?$',log,re.M)]
    require([(n,r,p) for n,r,p,_,_,_,_,_ in points]==[(n,r,p) for n in range(2) for r in range(2)
        for p in ('connected','source-removed','class-cleared','device-cleared','source-restored')], 'complete actual source-state observations')
    rows=read_capture(path);clock=bind(path,rows,statistics) if native else None
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane]);peer=bytes([2,0x41,0x58,0x54,0x43,lane])
    remote=ipaddress.IPv6Address(f'2001:db8:{lane+1}::1').packed
    controls=bytes([2,73,80,54,lane,0]);barriers={};streams={}
    for r in range(2):
        for companion in (False,True):streams[r,companion]=[]
    for index,row in enumerate(rows):
        frame=row['frame']
        if len(frame)>=21 and frame[12:14]==b'\x88\xc9':
            phase,answer=frame[19:21]
            require(len(frame)==60 and phase in [0,*range(1,8),*range(17,24)] and answer in (0,1) and
                (phase,answer) not in barriers and frame[:12]==(guest+controls if answer else controls+guest) and
                frame[14:19]==b'IP6L'+bytes([lane]) and not any(frame[21:]),'unique actual source Ethernet barriers')
            barriers[phase,answer]=index
        if not (len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6):continue
        value=packet(frame);outgoing=frame[6:12]==guest
        require(frame[:12]==(peer+guest if outgoing else guest+peer) and not value['flags']&4,'source TCP owner and no reset')
        matches=[]
        for r in range(2):
            for companion in (False,True):
                a=(50200 if companion else 50000)+r*10+lane;b=(50300 if companion else 50100)+r*10+lane
                if (value['source'],value['target'])==((a,b) if outgoing else (b,a)):matches.append((r,companion))
        require(len(matches)==1,'all TCP frames have complete known source tuples')
        r,companion=matches[0];local=ipaddress.IPv6Address(f'2001:db8:{lane+1}::{3 if companion else 2}').packed
        require(value['source_ip']+value['target_ip']==(local+remote if outgoing else remote+local),'actual retained or fresh full source address')
        streams[r,companion].append(dict(index=index,value=value,outgoing=outgoing,
            header=(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255)))
    require(set(barriers)=={(p,a) for p in [0,*range(1,8),*range(17,24)] for a in (0,1)},'complete source barriers in actual capture')
    observations=[]
    for (r,companion),flow in streams.items():
        syn=[x for x in flow if x['outgoing'] and x['value']['flags']==SYN]
        synack=[x for x in flow if not x['outgoing'] and x['value']['flags']==SYN|ACK]
        data=[x for x in flow if x['outgoing'] and x['value']['data']]
        echo=[x for x in flow if not x['outgoing'] and x['value']['data']]
        fin=[x for x in flow if x['outgoing'] and x['value']['flags']&FIN]
        peerfin=[x for x in flow if not x['outgoing'] and x['value']['flags']&FIN]
        tags=[9] if companion else [0,1,2,3,4]
        require(len(syn)==len(synack)==len(fin)==len(peerfin)==1 and len(data)==len(tags) and len(echo)==(1 if companion else 2),'complete source handshakes, exact output and closure')
        client=(syn[0]['value']['seq']+1)&0xffffffff;server=(synack[0]['value']['seq']+1)&0xffffffff
        require(synack[0]['value']['ack']==client and syn[0]['index']<synack[0]['index']<data[0]['index'],'source handshake sequences')
        for n,(item,tag) in enumerate(zip(data,tags)):
            expected=bytes((lane*53+r*31+tag*17+k*7)&255 for k in range(16))
            require(item['value']['data']==expected and item['value']['seq']==(client+n*16)&0xffffffff and
                item['value']['ack']==(server+(0 if n==0 else 16))&0xffffffff,'actual source output bytes and original stream sequence')
        for n,item in enumerate(echo):
            original=data[n if companion else (0 if n==0 else 4)]
            require(item['value']['data']==original['value']['data'] and item['value']['seq']==(server+n*16)&0xffffffff and
                item['value']['ack']==(original['value']['seq']+16)&0xffffffff and original['index']<item['index'],'actual source echo and acknowledgment')
        require(fin[0]['value']['seq']==(client+len(tags)*16)&0xffffffff and fin[0]['value']['ack']==(server+len(echo)*16)&0xffffffff and
            peerfin[0]['value']['seq']==(server+len(echo)*16)&0xffffffff and peerfin[0]['value']['ack']==(client+len(tags)*16+1)&0xffffffff,
            'complete actual source closure sequence')
        final=[x for x in flow if x['outgoing'] and x['index']>peerfin[0]['index']]
        require(len(final)==1 and final[0]['value']['flags']==ACK and not final[0]['value']['data'] and
            final[0]['value']['seq']==(client+len(tags)*16+1)&0xffffffff and final[0]['value']['ack']==(server+len(echo)*16+1)&0xffffffff,
            'actual source final acknowledgment')
        base=r*16
        if not companion:
            require(barriers[base+1,1]<syn[0]['index']<data[0]['index']<barriers[base+2,0] and
                all(barriers[base+2,1]<data[n]['index']<barriers[base+n+2,1] for n in range(1,4)) and
                barriers[base+6,1]<data[4]['index']<fin[0]['index']<final[0]['index']<barriers[base+7,0],
                'actual withdrawal, class/device invalidation, restore and final descriptor barriers')
            require(not any(not x['outgoing'] and barriers[base+2,0]<x['index']<barriers[base+6,0] for x in flow),
                'no TCP input is delivered to a withdrawn address')
        else:
            main=streams[r,False]
            removed=next(x for x in main if x['outgoing'] and x['value']['data']==
                bytes((lane*53+r*31+17+k*7)&255 for k in range(16)))
            require(barriers[base+2,1]<syn[0]['index']<data[0]['index']<final[0]['index']<removed['index'],
                'fresh companion proves usable route before retained-source output')
        observations.append(dict(round=r,companion=companion,data_headers=[x['header'] for x in data],
            syn_header=syn[0]['header'],fin_header=fin[0]['header'],data_frames=[x['index'] for x in data]))
    return dict(passed=True,
        lane=lane,actual_flows=4,actual_output_blocks=12,withdrawn_source_blocks=6,
        points=[p for p in points if p[0]==lane],observations=observations,clock=clock,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def verify(path,lane,log,native=False,statistics=None):
    result=_reconstruct(path,lane,log,native,statistics)
    expected=[]
    for round_ in range(2):
        expected.extend((lane,round_,phase,hops,traffic,0,binding,capacity) for phase,hops,traffic,binding,capacity in (
            ('connected',64,0,f'eth{lane}',5),('source-removed',64,0,f'eth{lane}',5),
            ('class-cleared',37,168,f'eth{lane}',5),('device-cleared',37,168,'-',0),
            ('source-restored',37,168,'-',0)))
    require(result['points']==expected,'fixed retained-source scalar controls and independent device state')
    for flow in result['observations']:
        companion=flow['companion']
        require(flow['syn_header']==(64,0) and flow['data_headers']==([(64,0)] if companion else
            [(64,0),(64,0),(37,168),(37,168),(37,168)]) and
            flow['fin_header']==((64,0) if companion else (37,168)),
            'fixed actual retained/fresh source output with class and device invalidation')
    result.update(retained_source_output=True,fresh_source_constrained=True,
        scope='established global TCP source removal while a companion retains the route; fresh binding and source selection stay constrained')
    return result


def damaged(path,lane,log,native,output,statistics=None):
    verify(path,lane,log,native,statistics)
    original=path.read_bytes();rows=read_capture(path)
    selected=[]
    for index,row in enumerate(rows):
        frame=row['frame']
        if len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6:
            value=packet(frame)
            if frame[6:12]==bytes([0x52,0x54,0,0x12,0x34,0x10+lane]) and value['data']:
                selected.append(index)
    require(len(selected)==12,'complete actual source-output mutation inventory')
    cases=[(f'packet-{number}-{field}',index,field) for number,index in enumerate(selected)
           for field in ('source','hop','class','payload','sequence')]
    for round_ in range(2):
        for phase in ('connected','source-removed','class-cleared','device-cleared','source-restored'):
            for field in ('hops','class','error','binding','capacity'):
                cases.append((f'point-{round_}-{phase}-{field}',None,f'point:{round_}:{phase}:{field}'))
    cases.extend([('completion',None,'completion'),('source-barrier',None,'barrier')])
    archive_path=output/(path.stem+'-damaged.zip')
    contexts=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        for name,index,field in cases:
            changed=deepcopy(rows);text=log
            if field=='completion':text=re.sub(r'^TCP6_SOURCE_LIFETIME_PASS .*\r?\n','',log,count=1,flags=re.M)
            elif field=='barrier':text=re.sub(rf'^TCP6_SOURCE_LIFETIME_PHASE_PASS lane={lane} phase=3\r?\n','',log,count=1,flags=re.M)
            elif field.startswith('point:'):
                _,round_,phase,selected_field=field.split(':')
                pattern=rf'^(TCP6_SOURCE_POINT lane={lane} round={round_} phase={phase} .*?{selected_field}=)([^ \r\n]+)'
                def change(match):return match[1]+('eth9' if selected_field=='binding' else str(int(match[2])+1))
                text,count=re.subn(pattern,change,log,count=1,flags=re.M)
                require(count==1,'selected actual source scalar control')
            else:
                frame=bytearray(changed[index]['frame'])
                if field=='source':frame[37]^=1
                elif field=='hop':frame[21]^=1
                elif field=='class':frame[14:18]=(int.from_bytes(frame[14:18],'big')^(1<<20)).to_bytes(4,'big')
                else:frame[54+((frame[66]>>4)*4 if field=='payload' else 4)]^=1
                size=int.from_bytes(frame[18:20],'big');frame[70:72]=bytes(2)
                frame[70:72]=struct.pack('!H',checksum(frame[22:54]+struct.pack('!I3xB',size,6)+frame[54:54+size]))
                changed[index]['frame']=bytes(frame)
            payloads={'lane.pcap':encode_capture(changed),'client.log':text.encode()}
            context=dict(lane=lane,native=native,changed_field=field,changed_frame=index,
                capture_sha256=hashlib.sha256(payloads['lane.pcap']).hexdigest(),
                log_sha256=hashlib.sha256(payloads['client.log']).hexdigest())
            if native:
                clocks=[json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()]
                if index is not None:clocks[index]['sha256']=hashlib.sha256(changed[index]['frame']).hexdigest()
                encoded=('\n'.join(json.dumps(row) for row in clocks)+'\n').encode()
                stats=deepcopy(statistics)
                stats.update(monotonic_receipts='lane.clocks.jsonl',monotonic_receipts_sha256=hashlib.sha256(encoded).hexdigest())
                context['statistics']=stats;payloads['lane.clocks.jsonl']=encoded
            payloads['context.json']=json.dumps(context).encode()
            for filename,body in payloads.items():archive.writestr(name+'/'+filename,body)
            contexts.append(dict(name=name,files=list(payloads)))
    rejected=[]
    with zipfile.ZipFile(archive_path) as archive:
        for row in contexts:
            with tempfile.TemporaryDirectory(prefix='tcp6-source-control-') as temporary:
                case=Path(temporary)
                for name in row['files']:(case/name).write_bytes(archive.read(row['name']+'/'+name))
                context=json.loads((case/'context.json').read_text())
                require(hashlib.sha256((case/'lane.pcap').read_bytes()).hexdigest()==context['capture_sha256'] and
                        hashlib.sha256((case/'client.log').read_bytes()).hexdigest()==context['log_sha256'],
                        'reopened source-lifetime control bytes')
                try:verify(case/'lane.pcap',lane,(case/'client.log').read_text(),native,context.get('statistics'))
                except ValueError as error:
                    require(not any(word in str(error) for word in ('checksum','arrival','clock','fingerprint')),
                            'source corruption reaches semantic rejection')
                    rejected.append(dict(name=row['name'],reason=str(error)))
                else:raise ValueError('damaged source-lifetime evidence passed: '+row['name'])
    require(len(rejected)==112 and path.read_bytes()==original,'all112 source controls reject and original stays unchanged')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

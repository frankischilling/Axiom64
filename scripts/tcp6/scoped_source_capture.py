# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct scoped source withdrawal and reject reopened damaged evidence."""
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

MARKER='TCP6_SCOPED_SOURCE_LIFETIME_PASS lanes=2 rounds_each=2 flows_each=4 data_each=12 withdrawn_each=6'

def _reconstruct(path,lane,log,native=False,statistics=None):
    require(log.splitlines().count(MARKER)==1,'actual source-lifetime application completion')
    phases=[tuple(map(int,row)) for row in re.findall(r'^TCP6_SCOPED_SOURCE_LIFETIME_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M)]
    require(phases==[(0,0),(1,0)]+[(n,r*16+s) for n in range(2) for r in range(2) for s in (1,8,9,10,2,3,4,5,6,7)],'all actual source-lifetime phases')
    fixtures=[tuple(map(int,row)) for row in re.findall(
        r'^TCP6_SCOPED_SOURCE_FIXTURE lane=(\d+) index=(\d+) removed_error=(-?\d+) bind_result=(-?\d+) bind_errno=(\d+)\r?$',log,re.M)]
    require(len(fixtures)==2 and [r[0] for r in fixtures]==[0,1] and
        len({r[1] for r in fixtures})==2 and all(index>0 and removed in (0,-99,-2) and bound==-1 and error==99
        for n,index,removed,bound,error in fixtures),'actual matching link-local source candidate fixtures')
    indices={n:index for n,index,_,_,_ in fixtures}
    bindings=[tuple(map(int,row)) for row in re.findall(
        r'^TCP6_SCOPED_SOURCE_BIND lane=(\d+) round=(\d+) result=(-?\d+) error=(\d+) other_index=(\d+) other_scope=(\d+)\r?$',log,re.M)]
    require(bindings==[(n,r,-1,99,indices[n^1],indices[n^1]) for n in range(2) for r in range(2)],
        'withdrawn source rejects fresh same-zone bind while identical other-zone address remains valid')
    points=[(int(n),int(r),phase,int(h),int(c),int(e),device,int(cap),int(index),int(local),int(peer))
        for n,r,phase,h,c,e,device,cap,index,local,peer in re.findall(
        r'^TCP6_SCOPED_SOURCE_POINT lane=(\d+) round=(\d+) phase=([a-z-]+) hops=(-?\d+) class=(\d+) error=(\d+) binding=([a-z0-9-]+) capacity=(\d+) index=(\d+) local_scope=(\d+) peer_scope=(\d+)\r?$',log,re.M)]
    require([(p[0],p[1],p[2]) for p in points]==[(n,r,p) for n in range(2) for r in range(2)
        for p in ('connected','device-cleared','device-restored','source-removed','class-cleared','source-held','source-restored')],
        'complete actual scoped state observations')
    rows=read_capture(path);clock=bind(path,rows,statistics) if native else None
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane]);peer=bytes([2,0x41,0x58,0x54,0x43,lane])
    remote=ipaddress.IPv6Address('fe80::1').packed
    controls=bytes([2,73,80,54,lane,0]);barriers={};streams={}
    for r in range(2):
        for companion in (False,True):streams[r,companion]=[]
    for index,row in enumerate(rows):
        frame=row['frame']
        if len(frame)>=21 and frame[12:14]==b'\x88\xcc':
            phase,answer=frame[19:21]
            require(len(frame)==60 and phase in [0]+[r*16+s for r in range(2) for s in (1,8,9,10,2,3,4,5,6,7)] and answer in (0,1) and
                (phase,answer) not in barriers and frame[:12]==(guest+controls if answer else controls+guest) and
                frame[14:19]==b'IP6Z'+bytes([lane]) and not any(frame[21:]),'unique actual source Ethernet barriers')
            barriers[phase,answer]=index
        if not (len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6):continue
        value=packet(frame);outgoing=frame[6:12]==guest
        require(frame[:12]==(peer+guest if outgoing else guest+peer) and not value['flags']&4,'source TCP owner and no reset')
        matches=[]
        for r in range(2):
            for companion in (False,True):
                a=(50200 if companion else 50000)+r*10;b=(50300 if companion else 50100)+r*10
                if (value['source'],value['target'])==((a,b) if outgoing else (b,a)):matches.append((r,companion))
        require(len(matches)==1,'all TCP frames have complete known source tuples')
        r,companion=matches[0];local=ipaddress.IPv6Address(f'fe80::{3 if companion else 2}').packed
        require(value['source_ip']+value['target_ip']==(local+remote if outgoing else remote+local),'actual retained or fresh full source address')
        streams[r,companion].append(dict(index=index,value=value,outgoing=outgoing,
            header=(frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255)))
    require(set(barriers)=={(p,a) for p in [0]+[r*16+s for r in range(2) for s in (1,8,9,10,2,3,4,5,6,7)] for a in (0,1)},'complete source barriers in actual capture')
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
            initial_ack=[x for x in flow if x['outgoing'] and x['value']['flags']==ACK and not x['value']['data'] and
                x['value']['seq']==(client+16)&0xffffffff and x['value']['ack']==(server+16)&0xffffffff and
                echo[0]['index']<x['index']<barriers[base+8,1]]
            require(initial_ack and barriers[base+8,1]<barriers[base+9,0]<barriers[base+9,1]<barriers[base+10,0]<barriers[base+10,1]<barriers[base+2,0],
                'actual echo acknowledgment before quiescent device clearing and restoration')
            require(not any(barriers[base+8,1]<x['index']<barriers[base+10,0] for x in flow),
                'scoped getter interval carries no TCP output or input while the zone is cleared')
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
        points=[p for p in points if p[0]==lane],indices=indices,zone_bindings=bindings,observations=observations,clock=clock,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def verify(path,lane,log,native=False,statistics=None):
    result=_reconstruct(path,lane,log,native,statistics)
    expected=[];index=result['indices'][lane]
    for round_ in range(2):
        expected.extend((lane,round_,phase,hops,traffic,0,binding,capacity,index,scope,scope)
            for phase,hops,traffic,binding,capacity,scope in (
            ('connected',64,0,f'eth{lane}',5,index),('device-cleared',64,0,'-',0,0),
            ('device-restored',64,0,f'eth{lane}',5,index),('source-removed',64,0,f'eth{lane}',5,index),
            ('class-cleared',37,168,f'eth{lane}',5,index),('source-held',37,168,f'eth{lane}',5,index),
            ('source-restored',37,168,f'eth{lane}',5,index)))
    require(result['points']==expected,'fixed native-derived scoped names, zone controls and source ownership')
    for flow in result['observations']:
        companion=flow['companion']
        require(flow['syn_header']==(64,0) and flow['data_headers']==([(64,0)] if companion else
            [(64,0),(64,0),(37,168),(37,168),(37,168)]) and
            flow['fin_header']==((64,0) if companion else (37,168)),
            'fixed actual retained/fresh source output with class and device invalidation')
    result.update(retained_source_output=True,fresh_source_constrained=True,
        scope='established link-local source withdrawal with identical tuples in separate zones; binding is restored before data',scoped_source_withdrawal=True,full_scoped_source_device_semantics_qualified=False)
    return result


def damaged(path,lane,log,native,output,statistics=None):
    actual=verify(path,lane,log,native,statistics)
    original=path.read_bytes();rows=read_capture(path)
    for n,row in enumerate(rows):row['_clock_source']=n
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane])
    selected=[n for n,row in enumerate(rows) if len(row['frame'])>=74 and row['frame'][12:14]==b'\x86\xdd'
        and row['frame'][20]==6 and row['frame'][6:12]==guest and packet(row['frame'])['data']]
    require(len(selected)==12,'all actual scoped output mutation inputs')
    variants=[]
    for number,index in enumerate(selected):
        for field in ('source','hop','class','payload','sequence','zone'):
            changed=deepcopy(rows);frame=bytearray(changed[index]['frame'])
            if field=='source':frame[37]^=1
            elif field=='hop':frame[21]^=1
            elif field=='class':frame[14:18]=(int.from_bytes(frame[14:18],'big')^(1<<20)).to_bytes(4,'big')
            elif field=='zone':frame[11]^=1
            else:frame[54+((frame[66]>>4)*4 if field=='payload' else 4)]^=1
            size=int.from_bytes(frame[18:20],'big');frame[70:72]=bytes(2)
            frame[70:72]=struct.pack('!H',checksum(frame[22:54]+struct.pack('!I3xB',size,6)+frame[54:54+size]))
            changed[index]['frame']=bytes(frame);variants.append((f'packet-{number}-{field}',changed,log))
    def scalar(name,pattern,field):
        def change(match):return match[1]+('eth9' if field=='binding' else str(int(match[2])+1))
        text,count=re.subn(pattern,change,log,count=1,flags=re.M)
        require(count==1,'one actual scoped scalar control')
        variants.append((name,deepcopy(rows),text))
    for round_ in range(2):
        for phase in ('connected','device-cleared','device-restored','source-removed','class-cleared','source-held','source-restored'):
            for field in ('hops','class','error','binding','capacity','index','local_scope','peer_scope'):
                scalar(f'point-{round_}-{phase}-{field}',
                    rf'^(TCP6_SCOPED_SOURCE_POINT lane={lane} round={round_} phase={phase} .*?{field}=)([^ \r\n]+)',field)
        for field in ('result','error','other_index','other_scope'):
            scalar(f'bind-{round_}-{field}',
                rf'^(TCP6_SCOPED_SOURCE_BIND lane={lane} round={round_} .*?{field}=)([^ \r\n]+)',field)
        barriers={tuple(row['frame'][19:21]):n for n,row in enumerate(rows)
            if row['frame'][12:14]==b'\x88\xcc'}
        base=round_*16;flow=next(f for f in actual['observations'] if f['round']==round_ and not f['companion'])
        first_data=flow['data_frames'][0];value=packet(rows[first_data]['frame'])
        echo_acks=[n for n in range(first_data+1,barriers[base+8,1]) if len(rows[n]['frame'])>=74
            and rows[n]['frame'][12:14]==b'\x86\xdd' and rows[n]['frame'][20]==6
            and rows[n]['frame'][6:12]==guest and packet(rows[n]['frame'])['flags']==ACK
            and not packet(rows[n]['frame'])['data'] and packet(rows[n]['frame'])['source']==value['source']
            and packet(rows[n]['frame'])['seq']==(value['seq']+16)&0xffffffff
            and packet(rows[n]['frame'])['ack']==(value['ack']+16)&0xffffffff]
        require(echo_acks,'actual complete echo acknowledgment witnesses')
        # Remove every matching witness; duplicate valid ACKs are permitted.
        changed=[deepcopy(row) for n,row in enumerate(rows) if n not in echo_acks]
        variants.append((f'quiet-{round_}-missing-echo-ack',changed,log))
        changed=deepcopy(rows);at=barriers[base+9,0];extra=deepcopy(rows[echo_acks[0]])
        extra['ns']=rows[at]['ns'];extra['_clock_source']=at;extra['_synthetic_insert']=True;changed.insert(at,extra)
        variants.append((f'quiet-{round_}-TCP-in-cleared-zone',changed,log))
        changed=deepcopy(rows);a,b=barriers[base+9,0],barriers[base+10,0]
        changed[a]['frame'],changed[b]['frame']=changed[b]['frame'],changed[a]['frame']
        variants.append((f'quiet-{round_}-device-order',changed,log))
    for n in range(2):
        for field in ('index','removed_error','bind_result','bind_errno'):
            scalar(f'fixture-{n}-{field}',rf'^(TCP6_SCOPED_SOURCE_FIXTURE lane={n} .*?{field}=)([^ \r\n]+)',field)
    variants.extend((('completion',deepcopy(rows),log.replace(MARKER,'')),
        ('source-barrier',deepcopy(rows),re.sub(rf'^TCP6_SCOPED_SOURCE_LIFETIME_PHASE_PASS lane={lane} phase=3\r?\n','',log,count=1,flags=re.M))))
    require(len(variants)==208,'complete scoped semantic-control inventory')
    clocks=([json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()] if native else [])
    if native:variants.extend((label,deepcopy(rows),log) for label in ('arrival-bound','capture-drop'))
    archive_path=output/(path.stem+'-damaged.zip');contexts=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        for label,changed,text in variants:
            payloads={'lane.pcap':encode_capture(changed),'client.log':text.encode()}
            context=dict(label=label,capture_sha256=hashlib.sha256(payloads['lane.pcap']).hexdigest(),
                log_sha256=hashlib.sha256(payloads['client.log']).hexdigest())
            if native:
                adjusted=[deepcopy(clocks[row['_clock_source']]) for row in changed]
                for n,(row,clock) in enumerate(zip(changed,adjusted)):
                    clock.update(frame=n,sha256=hashlib.sha256(row['frame']).hexdigest(),kernel_realtime_ns=row['ns'])
                    if row.get('_synthetic_insert'):
                        # The extra counterfeit frame gets an ordered point
                        # bracket before the original record, not an overlapping
                        # copy of that original receipt interval.
                        point=clock['receipt_monotonic_ns']
                        clock.update(arrival_lower_ns=point,receipt_monotonic_after_ns=point)
                if label=='arrival-bound':adjusted[0]['arrival_lower_ns']=adjusted[0]['receipt_monotonic_after_ns']+1
                encoded=('\n'.join(json.dumps(row) for row in adjusted)+'\n').encode();stats=deepcopy(statistics)
                stats.update(packets=len(changed),receipt_frames=len(changed),monotonic_receipts='lane.clocks.jsonl',
                    monotonic_receipts_sha256=hashlib.sha256(encoded).hexdigest())
                if label=='capture-drop':stats['dropped']=1
                context['statistics']=stats;payloads['lane.clocks.jsonl']=encoded
            payloads['context.json']=json.dumps(context).encode()
            for name,body in payloads.items():archive.writestr(label+'/'+name,body)
            contexts.append(dict(label=label,files=list(payloads)))
    rejected=[]
    with zipfile.ZipFile(archive_path) as archive:
        for item in contexts:
            with tempfile.TemporaryDirectory(prefix='axiom-scoped-control-') as temporary:
                case=Path(temporary)
                for name in item['files']:(case/name).write_bytes(archive.read(item['label']+'/'+name))
                context=json.loads((case/'context.json').read_text())
                require(hashlib.sha256((case/'lane.pcap').read_bytes()).hexdigest()==context['capture_sha256'] and
                    hashlib.sha256((case/'client.log').read_bytes()).hexdigest()==context['log_sha256'],'actual reopened scoped control bytes')
                try:verify(case/'lane.pcap',lane,(case/'client.log').read_text(),native,context.get('statistics'))
                except ValueError as error:
                    if item['label'] not in ('arrival-bound','capture-drop'):
                        require(not any(word in str(error) for word in ('checksum','arrival','clock','fingerprint')),
                            'scoped corruption reaches its semantic predicate: '+item['label'])
                    rejected.append(dict(name=item['label'],reason=str(error)))
                else:raise ValueError('corrupt scoped evidence passed: '+item['label'])
    require(len(rejected)==(210 if native else 208) and path.read_bytes()==original,'every scoped control rejects; actual input unchanged')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

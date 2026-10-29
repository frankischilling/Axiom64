# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct route transitions from both physical captures and raw route dumps."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import zipfile
import ipaddress
import re
import struct
from ipv4_expiry_capture import read_capture,encode_capture
from tcp6.capture import require
from tcp6.observation import bind
from tcp6.peer import packet
from tcp_fault_peer import ACK,FIN,SYN,checksum

MARKER='TCP6_ZONE_ROUTE_PASS lanes=2 rounds_each=2 flows=4 exchanges=20'

def verify(path,lane,log,native=False,statistics=None):
    require(log.splitlines().count(MARKER)==1,'one actual zone route application completion')
    phases=[tuple(map(int,row)) for row in re.findall(r'^TCP6_ZONE_ROUTE_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M)]
    expected=[(0,0),(1,0)]+[(p,n*64+r*16+s) for n in range(2) for r in range(2) for s in range(1,11) for p in range(2)]
    require(phases==expected,'every original ordered cross-link route fence')
    fixtures=[tuple(map(int,row)) for row in re.findall(
        r'^TCP6_ZONE_ROUTE_FIXTURE lane=(\d+) index=(\d+) removed_error=(-?\d+) bind_result=(-?\d+) bind_errno=(\d+)\r?$',log,re.M)]
    require(len(fixtures)==2 and [r[0] for r in fixtures]==[0,1] and len({r[1] for r in fixtures})==2 and
        all(index>0 and removed in (0,-99,-2) and result==-1 and error==99 for n,index,removed,result,error in fixtures),
        'matching actual local link addresses and distinct interface indices')
    indices={n:index for n,index,*_ in fixtures}
    points=[(int(n),int(r),phase,int(h),int(c),int(e),device,int(cap),int(index),int(local),int(peer))
        for n,r,phase,h,c,e,device,cap,index,local,peer in re.findall(
        r'^TCP6_ZONE_ROUTE_POINT lane=(\d+) round=(\d+) phase=([a-z-]+) hops=(-?\d+) class=(\d+) error=(\d+) binding=([a-z0-9-]+) capacity=(\d+) index=(\d+) local_scope=(\d+) peer_scope=(\d+)\r?$',log,re.M)]
    require(points==[(n,r,p,h,c,0,f'eth{n}' if bound else '-',5 if bound else 0,indices[n],indices[n] if bound else 0,indices[n] if bound else 0)
        for n in range(2) for r in range(2) for p,h,c,bound in (
        ('connected',64,0,True),('unbound',37,168,False),('fallback',37,168,False),
        ('preferred',37,168,False),('rebound',37,168,True))], 'fixed native-derived route-state getters and zones')
    remote=ipaddress.IPv6Address('fe80::1').packed;local=ipaddress.IPv6Address('fe80::2').packed
    snapshots={}
    for n,r,phase,hexadecimal in re.findall(
        r'^TCP6_ZONE_ROUTE_INVENTORY lane=(\d+) round=(\d+) phase=(configured|fallback|preferred) bytes=([a-f0-9]+)\r?$',log,re.M):
        n,r=int(n),int(r);data=bytes.fromhex(hexadecimal);require(12<=len(data)<=8192,'bounded raw zone route inventory')
        attributes={};at=12
        while at<len(data):
            require(at+4<=len(data),'complete zone route attribute header')
            size,kind=struct.unpack_from('<HH',data,at)
            require(size>=4 and at+size<=len(data) and kind not in attributes,'unique complete zone route attribute')
            attributes[kind]=data[at+4:at+size];at+=(size+3)&~3
        if data[0]!=10 or data[1]!=128 or data[5]!=4 or data[7]!=1 or attributes.get(1)!=remote:continue
        require(data[4]==254 and len(attributes.get(4,b''))==len(attributes.get(6,b''))==4 and
            5 not in attributes,'actual static direct main-table peer host routes')
        key=n,r,phase;snapshots.setdefault(key,[]).append((int.from_bytes(attributes[4],'little'),int.from_bytes(attributes[6],'little')))
    require(set(snapshots)=={(n,r,p) for n in range(2) for r in range(2) for p in ('configured','fallback','preferred')},
        'complete route transition snapshots')
    for (n,r,p),values in snapshots.items():
        expected=[(indices[n],20)]+([] if p=='fallback' else [(indices[n^1],10)])
        require(sorted(values)==sorted(expected),'exact preferred route withdrawal and restoration with surviving fallback')
    fences={};flows={(n,r):[] for n in range(2) for r in range(2)};clock=None
    for physical in range(2):
        current=path.parent/f'lane{physical}.pcap';rows=read_capture(current)
        if native and physical==lane:clock=bind(current,rows,statistics)
        guest=bytes([0x52,0x54,0,0x12,0x34,0x10+physical]);peer=bytes([2,0x41,0x58,0x54,0x43,physical])
        control=bytes([2,73,80,54,physical,0]);barriers={}
        for index,row in enumerate(rows):
            f=row['frame']
            if len(f)>=21 and f[12:14]==b'\x88\xcd':
                phase,answer=f[19:21]
                require(len(f)==60 and phase in [0]+[n*64+r*16+s for n in range(2) for r in range(2) for s in range(1,11)] and
                    answer in (0,1) and (phase,answer) not in barriers and
                    f[:12]==(guest+control if answer else control+guest) and f[14:19]==b'IP6G'+bytes([physical]) and
                    not any(f[21:]),'complete unique physical route fences')
                barriers[phase,answer]=index
            if not(len(f)>=74 and f[12:14]==b'\x86\xdd' and f[20]==6):continue
            value=packet(f);outgoing=f[6:12]==guest
            require(f[:12]==(peer+guest if outgoing else guest+peer) and not value['flags']&4,
                'every route TCP frame has its actual physical MAC owner and no reset')
            require(value['source_ip']+value['target_ip']==(local+remote if outgoing else remote+local),
                'unchanged full IPv6 route stream addresses')
            matches=[(n,r) for n,r in flows if (value['source'],value['target'])==
                ((52000+n*100+r*10,53000+n*100+r*10) if outgoing else (53000+n*100+r*10,52000+n*100+r*10))]
            require(len(matches)==1,'every route TCP frame has one complete port tuple')
            flows[matches[0]].append(dict(physical=physical,index=index,value=value,outgoing=outgoing,
                header=(f[21],(int.from_bytes(f[14:18],'big')>>20)&255)))
        require(list(barriers)==[(p,a) for p in [0]+[n*64+r*16+s for n in range(2) for r in range(2) for s in range(1,11)] for a in (0,1)],
            'both captures independently retain every ordered cross-link fence')
        fences[physical]=barriers
    observations=[]
    for (origin,r),flow in flows.items():
        syn=[x for x in flow if x['outgoing'] and x['value']['flags']==SYN]
        synack=[x for x in flow if not x['outgoing'] and x['value']['flags']==SYN|ACK]
        data=[x for x in flow if x['outgoing'] and x['value']['data']]
        echo=[x for x in flow if not x['outgoing'] and x['value']['data']]
        fin=[x for x in flow if x['outgoing'] and x['value']['flags']&FIN]
        peerfin=[x for x in flow if not x['outgoing'] and x['value']['flags']&FIN]
        require(len(syn)==len(synack)==len(fin)==len(peerfin)==1 and len(data)==len(echo)==5,
            'complete actual cross-link route handshake, five exchanges and closure')
        require(all(x['physical']==origin for x in syn+synack+fin+peerfin),'initial and rebound closure physical zone')
        client=(syn[0]['value']['seq']+1)&0xffffffff;server=(synack[0]['value']['seq']+1)&0xffffffff
        require(synack[0]['value']['ack']==client and syn[0]['index']<synack[0]['index'],
            'actual original cross-link route handshake sequences')
        data.sort(key=lambda x:(x['value']['seq']-client)&0xffffffff)
        echo.sort(key=lambda x:(x['value']['seq']-server)&0xffffffff)
        base=origin*64+r*16;zones=[]
        for tag,(sent,received) in enumerate(zip(data,echo)):
            zone=origin^(tag in (1,3));barriers=fences[zone]
            required=bytes((origin*53+r*31+tag*17+n*7)&255 for n in range(16))
            require(sent['physical']==received['physical']==zone and sent['value']['data']==received['value']['data']==required and
                sent['value']['seq']==(client+tag*16)&0xffffffff and sent['value']['ack']==(server+tag*16)&0xffffffff and
                received['value']['seq']==(server+tag*16)&0xffffffff and received['value']['ack']==(client+(tag+1)*16)&0xffffffff,
                'actual original stream bytes, TCP sequence, echo and exact route zone')
            require(sent['header']==((64,0) if tag==0 else (37,168)) and
                barriers[base+tag*2+1,1]<sent['index']<received['index']<barriers[base+tag*2+2,0],
                'actual header controls and per-link causal route fences')
            if tag<4:
                acknowledgments=[x for x in flow if x['outgoing'] and x['physical']==zone and
                    x['value']['flags']==ACK and not x['value']['data'] and
                    x['value']['seq']==(client+(tag+1)*16)&0xffffffff and x['value']['ack']==(server+(tag+1)*16)&0xffffffff and
                    received['index']<x['index']<barriers[base+tag*2+2,1]]
                require(acknowledgments,'actual complete echo acknowledgment before the next route change')
            zones.append(zone)
        require(fin[0]['value']['seq']==(client+80)&0xffffffff and fin[0]['value']['ack']==(server+80)&0xffffffff and
            peerfin[0]['value']['seq']==(server+80)&0xffffffff and peerfin[0]['value']['ack']==(client+81)&0xffffffff and
            data[-1]['index']<fin[0]['index']<peerfin[0]['index'] and fin[0]['header']==(37,168),
            'complete rebound route FIN sequence and controls')
        final=[x for x in flow if x['outgoing'] and x['physical']==origin and x['index']>peerfin[0]['index']]
        require(len(final)==1 and final[0]['value']['flags']==ACK and not final[0]['value']['data'] and
            final[0]['value']['seq']==(client+81)&0xffffffff and final[0]['value']['ack']==(server+81)&0xffffffff and
            final[0]['index']<fences[origin][base+10,0], 'actual final rebound descriptor acknowledgment')
        require(len([x for x in flow if not x['outgoing']])==7 and
            all(x['value']['flags'] in (ACK,ACK|8) for x in data) and
            syn[0]['value']['ack']==0 and fin[0]['value']['flags']==peerfin[0]['value']['flags']==FIN|ACK,
            'every incoming route TCP frame and exact outgoing control flags')
        for x in flow:
            if not x['outgoing'] or x in syn+data+fin+final:continue
            value=x['value'];k=((value['seq']-client)&0xffffffff)//16
            require(value['flags']==ACK and not value['data'] and 0<=k<=5 and
                value['seq']==(client+k*16)&0xffffffff and value['ack']==(server+k*16)&0xffffffff and
                x['physical']==(origin if not k else origin^((k-1) in (1,3))),
                'every extra route acknowledgment retains exact sequence and actual zone')
        observations.append(dict(origin=origin,round=r,zones=zones,
            data_frames=[dict(lane=x['physical'],index=x['index']) for x in data]))
    return dict(passed=True,lane=lane,actual_flows=2,actual_output_blocks=10,actual_route_snapshots=6,actual_route_fence_pairs=len(fences[lane])//2-1,
        points=[p for p in points if p[0]==lane],route_snapshots={f'{r}-{p}':v for (n,r,p),v in snapshots.items() if n==lane},
        observations=observations,clock=clock,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        scoped_route_transitions=True,full_scoped_source_device_semantics_qualified=False)


def damaged(path,lane,log,native,output,statistics=None):
    actual=verify(path,lane,log,native,statistics);rows=read_capture(path)
    original=path.read_bytes();other=path.parent/f'lane{lane^1}.pcap';companion=other.read_bytes()
    for n,row in enumerate(rows):row['_clock_source']=n
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane])
    tcp=[n for n,row in enumerate(rows) if len(row['frame'])>=74 and row['frame'][12:14]==b'\x86\xdd'
        and row['frame'][20]==6]
    data=[n for n in tcp if rows[n]['frame'][6:12]==guest and packet(rows[n]['frame'])['data']]
    echoes=[n for n in tcp if rows[n]['frame'][6:12]!=guest and packet(rows[n]['frame'])['data']]
    require(len(data)==len(echoes)==10,'complete actual physical route mutation inputs')
    variants=[]
    for collection,fields in ((data,('source','hop','class','payload','sequence','zone')),
                              (echoes,('payload','sequence','acknowledgment'))):
        for number,index in enumerate(collection):
            for field in fields:
                changed=deepcopy(rows);f=bytearray(changed[index]['frame'])
                if field=='source':f[37]^=1
                elif field=='hop':f[21]^=1
                elif field=='class':f[14:18]=(int.from_bytes(f[14:18],'big')^(1<<20)).to_bytes(4,'big')
                elif field=='zone':f[11]^=1
                elif field=='payload':f[54+(f[66]>>4)*4]^=1
                elif field=='sequence':f[58]^=1
                else:f[62]^=1
                size=int.from_bytes(f[18:20],'big');f[70:72]=bytes(2)
                f[70:72]=struct.pack('!H',checksum(f[22:54]+struct.pack('!I3xB',size,6)+f[54:54+size]))
                changed[index]['frame']=bytes(f)
                variants.append((f'{"output" if collection is data else "echo"}-{number}-{field}',changed,log))
    ack_controls=0
    for observation in actual['observations']:
        for tag,location in enumerate(observation['data_frames'][:4]):
            if location['lane']!=lane:continue
            sent=packet(rows[location['index']]['frame'])
            selected=[n for n in tcp if rows[n]['frame'][6:12]==guest and
                packet(rows[n]['frame'])['source']==sent['source'] and
                packet(rows[n]['frame'])['flags']==ACK and not packet(rows[n]['frame'])['data'] and
                packet(rows[n]['frame'])['seq']==(sent['seq']+16)&0xffffffff and
                packet(rows[n]['frame'])['ack']==(sent['ack']+16)&0xffffffff]
            require(selected,'all matching actual route echo acknowledgment witnesses')
            variants.append((f'missing-echo-ack-{observation["origin"]}-{observation["round"]}-{tag}',
                [deepcopy(row) for n,row in enumerate(rows) if n not in selected],log))
            ack_controls+=1
    require(ack_controls==8,'all route transition acknowledgment controls')
    def scalar(name,pattern,field):
        def change(match):return match[1]+('eth9' if field=='binding' else str(int(match[2])+1))
        text,count=re.subn(pattern,change,log,count=1,flags=re.M)
        require(count==1,'one actual route scalar mutation input')
        variants.append((name,deepcopy(rows),text))
    for round_ in range(2):
        for phase in ('connected','unbound','fallback','preferred','rebound'):
            for field in ('hops','class','error','binding','capacity','index','local_scope','peer_scope'):
                scalar(f'point-{round_}-{phase}-{field}',
                    rf'^(TCP6_ZONE_ROUTE_POINT lane={lane} round={round_} phase={phase} .*?{field}=)([^ \r\n]+)',field)
    for n in range(2):
        for field in ('index','removed_error','bind_result','bind_errno'):
            scalar(f'fixture-{n}-{field}',rf'^(TCP6_ZONE_ROUTE_FIXTURE lane={n} .*?{field}=)([^ \r\n]+)',field)
    routes=[]
    pattern=rf'^TCP6_ZONE_ROUTE_INVENTORY lane={lane} round=(\d+) phase=([a-z]+) bytes=([a-f0-9]+)\r?$'
    for match in re.finditer(pattern,log,re.M):
        data_=bytes.fromhex(match[3]);attrs={};at=12
        while at<len(data_):
            size,kind=struct.unpack_from('<HH',data_,at);attrs[kind]=(at,size);at+=(size+3)&~3
        destination=attrs.get(1)
        if (data_[0:2]==bytes([10,128]) and data_[5]==4 and destination and
                data_[destination[0]+4:destination[0]+destination[1]]==bytes.fromhex('fe800000000000000000000000000001')):
            routes.append((match,data_,attrs))
    require(len(routes)==10,'all actual preferred and fallback route rows to corrupt')
    for number,(match,data_,attrs) in enumerate(routes):
        for field in ('interface','metric','prefix','destination'):
            modified=bytearray(data_)
            if field=='interface':modified[attrs[4][0]+4]^=1
            elif field=='metric':modified[attrs[6][0]+4]^=1
            elif field=='prefix':modified[1]^=1
            else:modified[attrs[1][0]+19]^=1
            start,end=match.span(3);text=log[:start]+modified.hex()+log[end:]
            variants.append((f'route-{number}-{field}',deepcopy(rows),text))
    replies=[n for n,row in enumerate(rows) if row['frame'][12:14]==b'\x88\xcd' and row['frame'][19] and row['frame'][20]==1]
    require(len(replies)==40,'all actual route transition fences')
    for n,index in enumerate(replies):
        variants.append((f'missing-fence-{n}',[deepcopy(row) for i,row in enumerate(rows) if i!=index],log))
    variants.extend((('completion',deepcopy(rows),log.replace(MARKER,'')),
        ('logged-fence',deepcopy(rows),re.sub(rf'^TCP6_ZONE_ROUTE_PHASE_PASS lane={lane} phase=1\r?\n','',log,count=1,flags=re.M))))
    require(len(variants)==268,'complete physical route semantic control inventory')
    clocks=([json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()] if native else [])
    if native:variants.extend((name,deepcopy(rows),log) for name in ('arrival-bound','capture-drop'))
    archive_path=output/(path.stem+'-damaged.zip');contexts=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('original/'+other.name,companion)
        for name,changed,text in variants:
            payloads={path.name:encode_capture(changed),'client.log':text.encode()}
            context=dict(name=name,capture_sha256=hashlib.sha256(payloads[path.name]).hexdigest(),
                log_sha256=hashlib.sha256(payloads['client.log']).hexdigest(),companion_sha256=hashlib.sha256(companion).hexdigest())
            if native:
                adjusted=[deepcopy(clocks[row['_clock_source']]) for row in changed]
                for n,(row,clock) in enumerate(zip(changed,adjusted)):
                    clock.update(frame=n,sha256=hashlib.sha256(row['frame']).hexdigest(),kernel_realtime_ns=row['ns'])
                if name=='arrival-bound':adjusted[0]['arrival_lower_ns']=adjusted[0]['receipt_monotonic_after_ns']+1
                encoded=('\n'.join(json.dumps(row) for row in adjusted)+'\n').encode();stats=deepcopy(statistics)
                stats.update(packets=len(changed),receipt_frames=len(changed),monotonic_receipts=path.with_suffix('.clocks.jsonl').name,
                    monotonic_receipts_sha256=hashlib.sha256(encoded).hexdigest())
                if name=='capture-drop':stats['dropped']=1
                context['statistics']=stats;payloads[path.with_suffix('.clocks.jsonl').name]=encoded
            payloads['context.json']=json.dumps(context).encode()
            for filename,body in payloads.items():archive.writestr(name+'/'+filename,body)
            contexts.append(dict(name=name,files=list(payloads)))
    rejected=[]
    with zipfile.ZipFile(archive_path) as archive:
        for item in contexts:
            with tempfile.TemporaryDirectory(prefix='axiom-zone-route-control-') as temporary:
                case=Path(temporary)
                for filename in item['files']:(case/filename).write_bytes(archive.read(item['name']+'/'+filename))
                (case/other.name).write_bytes(archive.read('original/'+other.name))
                context=json.loads((case/'context.json').read_text())
                require(hashlib.sha256((case/path.name).read_bytes()).hexdigest()==context['capture_sha256'] and
                    hashlib.sha256((case/other.name).read_bytes()).hexdigest()==context['companion_sha256'] and
                    hashlib.sha256((case/'client.log').read_bytes()).hexdigest()==context['log_sha256'],
                    'exact reopened physical route control and companion bytes')
                try:verify(case/path.name,lane,(case/'client.log').read_text(),native,context.get('statistics'))
                except ValueError as error:
                    if item['name'] not in ('arrival-bound','capture-drop'):
                        require(not any(word in str(error) for word in ('checksum','arrival','clock','fingerprint')),
                            'route control reaches intended semantic predicate: '+item['name'])
                    rejected.append(dict(name=item['name'],reason=str(error)))
                else:raise ValueError('corrupt physical route evidence passed: '+item['name'])
    require(len(rejected)==(270 if native else 268) and path.read_bytes()==original and other.read_bytes()==companion,
        'every route control rejects and both actual captures remain unchanged')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

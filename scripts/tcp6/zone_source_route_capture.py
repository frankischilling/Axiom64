# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen original source inventories, companion traffic and retained route streams."""
import hashlib
import ipaddress
from pathlib import Path
import re
import struct
import tempfile
from ipv4_expiry_capture import read_capture,encode_capture
from tcp6.capture import require
from tcp6.observation import bind
from tcp6.peer import packet
from tcp6.zone_route_capture import verify as route_verify
from tcp_fault_peer import ACK,FIN,SYN

MARKER='TCP6_ZONE_SOURCE_ROUTE_PASS lanes=2 rounds_each=2 retained_flows=4 companion_flows=4'
LOCAL=ipaddress.IPv6Address('fe80::2').packed
COMPANION=ipaddress.IPv6Address('fe80::3').packed
REMOTE=ipaddress.IPv6Address('fe80::1').packed

def verify(path,lane,log,native=False,statistics=None):
    require(log.splitlines().count(MARKER)==1,'one actual combined source and route completion')
    indices={int(n):int(index) for n,index in re.findall(r'^TCP6_ZONE_ROUTE_FIXTURE lane=(\d+) index=(\d+)',log,re.M)}
    require(set(indices)=={0,1} and len(set(indices.values()))==2,'both actual source route interface indices')
    inventories={};inventory_positions={};order=[]
    pattern=r'^TCP6_ZONE_SOURCE_ROUTE_ADDRESS lane=(\d+) round=(\d+) phase=(initial|withdrawn|fallback-withdrawn|input-restored|restored) bytes=([a-f0-9]+)\r?$'
    matches=list(re.finditer(pattern,log,re.M))
    require(len(matches)==log.count('TCP6_ZONE_SOURCE_ROUTE_ADDRESS '),'all address inventory rows parse exactly')
    for match in matches:
        origin,round_=int(match[1]),int(match[2]);phase=match[3];key=origin,round_,phase
        if not order or order[-1]!=key:order.append(key)
        data=bytes.fromhex(match[4]);require(8<=len(data)<=8192,'bounded original address record')
        attrs={};at=8
        while at<len(data):
            require(at+4<=len(data),'complete address attribute header')
            size,kind=struct.unpack_from('<HH',data,at)
            require(size>=4 and at+size<=len(data) and kind not in attrs,'unique complete original address attribute')
            attrs[kind]=data[at+4:at+size];at+=(size+3)&~3
        inventories.setdefault(key,[]);inventory_positions.setdefault(key,match.start())
        address=attrs.get(1,attrs.get(2))
        if data[0]!=10 or address not in (LOCAL,COMPANION):continue
        index=int.from_bytes(data[4:8],'little');flags=int.from_bytes(attrs[8],'little') if 8 in attrs else data[2]
        require(data[1]==64 and data[3]==253 and index in indices.values() and not flags&(0x40|8) and
            len(attrs.get(6,b''))==16 and attrs[6][:8]==b'\xff'*8,
            'actual ready permanent scoped address ownership and original lifetimes')
        inventories[key].append((index,address))
    require(order==[(n,r,p) for n in range(2) for r in range(2) for p in ('initial','withdrawn','fallback-withdrawn','input-restored','restored')],
        'all ordered initial withdrawn and restored source inventories')
    for (origin,round_,phase),values in inventories.items():
        wanted=[(indices[origin^1],LOCAL),(indices[origin],COMPANION if phase in ('withdrawn','fallback-withdrawn') else LOCAL)]
        if phase=='input-restored':wanted.append((indices[origin],COMPANION))
        require(sorted(values)==sorted(wanted),'source absent only in its withdrawn physical zone with a surviving companion')
    binds=[tuple(map(int,m)) for m in re.findall(
        r'^TCP6_ZONE_SOURCE_ROUTE_BIND lane=(\d+) round=(\d+) stage=(\d+) zone=(\d+) index=(\d+) result=(-?\d+) error=(\d+)\r?$',log,re.M)]
    require(binds==[(n,r,restored,n^other,indices[n^other],0 if other or restored>=2 else -1,0 if other or restored>=2 else 99)
        for n in range(2) for r in range(2) for restored in range(4) for other in range(2)],
        'all exact native-derived fresh same-zone denial other-zone success and restored binds')
    require(len(binds)==log.count('TCP6_ZONE_SOURCE_ROUTE_BIND '),'every actual fresh-bind record parses exactly')
    companions=[tuple(map(int,m)) for m in re.findall(
        r'^TCP6_ZONE_SOURCE_ROUTE_COMPANION lane=(\d+) round=(\d+) source=(\d+) local_port=(\d+) peer_port=(\d+) closed=(\d+)\r?$',log,re.M)]
    require(companions==[(n,r,3,54000+n*100+r*10,55000+n*100+r*10,1) for n in range(2) for r in range(2)],
        'all fresh automatic companion selected-source and final-release observations')
    require(len(companions)==log.count('TCP6_ZONE_SOURCE_ROUTE_COMPANION '),'every actual companion record parses exactly')
    phases=[tuple(map(int,m)) for m in re.findall(r'^TCP6_ZONE_ROUTE_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M)]
    require(phases==[(0,0),(1,0)]+[(p,n*64+r*16+s) for n in range(2) for r in range(2)
        for s in (1,2,3,4,5,11,12,6,7,8,9,10) for p in range(2)],'all original ordered ownership and route fences')
    route_log='\n'.join(line for line in log.splitlines() if not
        (line.startswith('TCP6_ZONE_ROUTE_PHASE_PASS ') and int(line.rsplit('=',1)[1])%16 in (11,12)))+'\n'
    phase_positions={(int(n),int(p)):m.start() for m in re.finditer(
        r'^TCP6_ZONE_ROUTE_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M) for n,p in [m.groups()]}
    for origin in range(2):
        for round_ in range(2):
            base=origin*64+round_*16
            for before,after,first,last in ((2,3,'initial','withdrawn'),(11,12,'fallback-withdrawn','input-restored'),(8,9,'restored','restored')):
                require(max(phase_positions[p,base+before] for p in range(2))<inventory_positions[origin,round_,first]<=
                    inventory_positions[origin,round_,last]<min(phase_positions[p,base+after] for p in range(2)),
                    'actual raw source observations fall between their acknowledged ownership fences')
    originals={};filtered={};flows={(n,r):[] for n in range(2) for r in range(2)};ownership_fences={};clock=None
    for physical in range(2):
        capture=path.parent/f'lane{physical}.pcap';rows=read_capture(capture);originals[physical]=rows;filtered[physical]=[]
        if native and physical==lane:clock=bind(capture,rows,statistics)
        guest=bytes([0x52,0x54,0,0x12,0x34,0x10+physical]);peer=bytes([2,0x41,0x58,0x54,0x43,physical])
        ownership_fences[physical]={}
        expected_ownership=[n*64+r*16+s for n in range(2) for r in range(2) for s in (11,12)]
        for index,row in enumerate(rows):
            frame=row['frame'];selected=[]
            if len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6:
                value=packet(frame);outgoing=frame[6:12]==guest
                selected=[(n,r) for n,r in flows if (value['source'],value['target'])==
                    ((54000+n*100+r*10,55000+n*100+r*10) if outgoing else (55000+n*100+r*10,54000+n*100+r*10))]
                if selected:
                    require(len(selected)==1 and selected[0][0]==physical and frame[:12]==(peer+guest if outgoing else guest+peer) and
                        value['source_ip']+value['target_ip']==(COMPANION+REMOTE if outgoing else REMOTE+COMPANION),
                        'fresh companion exact physical interface addresses and ports')
                    require(not outgoing or (frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255)==(64,0),
                        'every fresh companion output retains its actual default controls')
                    flows[selected[0]].append(dict(index=index,value=value,outgoing=outgoing))
            extra_fence=len(frame)==60 and frame[12:14]==b'\x88\xcd' and frame[19]%16 in (11,12)
            if extra_fence:
                phase,answer=frame[19:21];control=bytes([2,73,80,54,physical,0])
                require(phase in expected_ownership and answer in (0,1) and (phase,answer) not in ownership_fences[physical] and
                    frame[:12]==(guest+control if answer else control+guest) and frame[14:19]==b'IP6G'+bytes([physical]) and
                    not any(frame[21:]),'every actual ownership fence has its full physical envelope')
                ownership_fences[physical][phase,answer]=index
            if not selected and not extra_fence:filtered[physical].append(row)
        require(list(ownership_fences[physical])==[(phase,a) for phase in expected_ownership for a in (0,1)],
            'both original captures retain all ordered ownership requests and acknowledgments')
    # Native clocks bind every original physical frame above. The route decoder
    # sees a lossless subset with unchanged packet bytes and timestamps, while
    # this decoder checks every removed companion frame separately below.
    with tempfile.TemporaryDirectory(prefix='axiom-source-route-read-') as temporary:
        directory=Path(temporary)
        for physical,rows in filtered.items():(directory/f'lane{physical}.pcap').write_bytes(encode_capture(rows))
        route=route_verify(directory/path.name,lane,route_log,native=False)
    for origin in range(2):
        for round_ in range(2):
            base=origin*64+round_*16;rows=originals[origin]
            fences=ownership_fences[origin]
            sent=[];echo=[];acks=[]
            for index,row in enumerate(rows):
                frame=row['frame']
                if not(len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6):continue
                value=packet(frame);ports=(value['source'],value['target']);local=52000+origin*100+round_*10
                expected=bytes((origin*53+round_*31+2*17+n*7)&255 for n in range(16))
                if ports==(local,local+1000) and value['data']==expected:sent.append((index,value))
                if ports==(local+1000,local) and value['data']==expected:echo.append((index,value))
            require(len(sent)==len(echo)==1 and sent[0][0]<fences[base+11,1]<fences[base+12,0]<echo[0][0]<fences[base+12,1],
                'actual withdrawn fallback packet observed before restoring ownership and releasing its echo')
            for index,row in enumerate(rows):
                frame=row['frame']
                if not(len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6):continue
                value=packet(frame)
                if ((value['source'],value['target'])==(local,local+1000) and value['flags']==ACK and not value['data'] and
                        value['seq']==(sent[0][1]['seq']+16)&0xffffffff and value['ack']==(sent[0][1]['ack']+16)&0xffffffff):
                    acks.append(index)
            require(any(echo[0][0]<index<fences[base+12,1] for index in acks),'actual fallback TCP echo acknowledgment precedes ownership fence completion')
    observations=[]
    for (origin,round_),flow in flows.items():
        syn=[x for x in flow if x['outgoing'] and x['value']['flags']==SYN]
        synack=[x for x in flow if not x['outgoing'] and x['value']['flags']==SYN|ACK]
        data=[x for x in flow if x['outgoing'] and x['value']['data']]
        echo=[x for x in flow if not x['outgoing'] and x['value']['data']]
        fin=[x for x in flow if x['outgoing'] and x['value']['flags']&FIN]
        peerfin=[x for x in flow if not x['outgoing'] and x['value']['flags']&FIN]
        require(len(syn)==len(synack)==len(data)==len(echo)==len(fin)==len(peerfin)==1,
            'one complete actual fresh companion handshake exchange and close')
        client=(syn[0]['value']['seq']+1)&0xffffffff;server=(synack[0]['value']['seq']+1)&0xffffffff
        expected=bytes((origin*53+round_*31+9*17+n*7)&255 for n in range(16))
        require(syn[0]['value']['ack']==0 and synack[0]['value']['ack']==client and
            data[0]['value']['data']==echo[0]['value']['data']==expected and
            data[0]['value']['seq']==client and data[0]['value']['ack']==server and
            echo[0]['value']['seq']==server and echo[0]['value']['ack']==(client+16)&0xffffffff and
            data[0]['value']['flags'] in (ACK,ACK|8) and echo[0]['value']['flags']==ACK|8,
            'original automatic companion source carries exact current TCP bytes and sequences')
        require(fin[0]['value']['flags']==peerfin[0]['value']['flags']==FIN|ACK and
            fin[0]['value']['seq']==(client+16)&0xffffffff and fin[0]['value']['ack']==(server+16)&0xffffffff and
            peerfin[0]['value']['seq']==(server+16)&0xffffffff and peerfin[0]['value']['ack']==(client+17)&0xffffffff,
            'actual complete fresh companion FIN exchange')
        final=[x for x in flow if x['outgoing'] and x['index']>peerfin[0]['index']]
        require(len(final)==1 and final[0]['value']['flags']==ACK and not final[0]['value']['data'] and
            final[0]['value']['seq']==(client+17)&0xffffffff and final[0]['value']['ack']==(server+17)&0xffffffff,
            'actual final fresh companion release acknowledgment')
        fences={(row['frame'][19],row['frame'][20]):index for index,row in enumerate(originals[origin])
            if len(row['frame'])==60 and row['frame'][12:14]==b'\x88\xcd'}
        base=origin*64+round_*16
        require(fences[base+2,1]<syn[0]['index']<synack[0]['index']<data[0]['index']<echo[0]['index']<
            fin[0]['index']<peerfin[0]['index']<final[0]['index']<fences[base+3,0],
            'fresh usable-source traffic completes after initial echo acknowledgment and before route changes')
        require(len([x for x in flow if not x['outgoing']])==3,'every original incoming companion frame accounted')
        for item in flow:
            if not item['outgoing'] or item in syn+data+fin+final:continue
            value=item['value']
            require(value['flags']==ACK and not value['data'] and
                ((synack[0]['index']<item['index']<data[0]['index'] and value['seq']==client and value['ack']==server) or
                 (echo[0]['index']<item['index']<fin[0]['index'] and value['seq']==(client+16)&0xffffffff and value['ack']==(server+16)&0xffffffff)),
                'every extra companion acknowledgment has its exact position and sequence')
        observations.append(dict(origin=origin,round=round_,output_index=data[0]['index'],final_index=final[0]['index']))
    route.update(clock=clock,sha256=hashlib.sha256(path.read_bytes()).hexdigest(),combined_scoped_source_route=True,
        actual_companion_flows=2,actual_source_withdrawals=2,actual_source_snapshots=10,actual_fresh_bind_observations=16,actual_ownership_fence_pairs=8,
        companion_observations=[o for o in observations if o['origin']==lane])
    return route


def damaged(path,lane,log,native,output,statistics=None):
    from copy import deepcopy
    import json
    import zipfile
    from tcp_fault_peer import checksum
    verify(path,lane,log,native,statistics)
    rows=read_capture(path);original=path.read_bytes();other=path.parent/f'lane{lane^1}.pcap';companion=other.read_bytes()
    for n,row in enumerate(rows):row['_clock_source']=n
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane]);variants=[]
    tcp=[n for n,row in enumerate(rows) if len(row['frame'])>=74 and row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]==6]
    outgoing=[n for n in tcp if rows[n]['frame'][6:12]==guest]
    outputs=[n for n in outgoing if packet(rows[n]['frame'])['data']]
    require(len(outputs)==12,'all actual retained and fresh companion output mutation inputs')
    for number,index in enumerate(outputs):
        for field in ('source','hop','class','payload','sequence','zone'):
            changed=deepcopy(rows);frame=bytearray(changed[index]['frame'])
            if field=='source':frame[37]^=1
            elif field=='hop':frame[21]^=1
            elif field=='class':frame[14:18]=(int.from_bytes(frame[14:18],'big')^(1<<20)).to_bytes(4,'big')
            elif field=='zone':frame[11]^=1
            elif field=='payload':frame[54+(frame[66]>>4)*4]^=1
            else:frame[58]^=1
            size=int.from_bytes(frame[18:20],'big');frame[70:72]=bytes(2)
            frame[70:72]=struct.pack('!H',checksum(frame[22:54]+struct.pack('!I3xB',size,6)+frame[54:54+size]))
            changed[index]['frame']=bytes(frame);variants.append((f'output-{number}-{field}',changed,log))
    echoes=[n for n in tcp if rows[n]['frame'][6:12]!=guest and packet(rows[n]['frame'])['data']]
    require(len(echoes)==12,'all actual retained and companion echo mutation inputs')
    for number,index in enumerate(echoes):
        for field in ('payload','sequence','acknowledgment'):
            changed=deepcopy(rows);frame=bytearray(changed[index]['frame'])
            if field=='payload':frame[54+(frame[66]>>4)*4]^=1
            elif field=='sequence':frame[58]^=1
            else:frame[62]^=1
            size=int.from_bytes(frame[18:20],'big');frame[70:72]=bytes(2)
            frame[70:72]=struct.pack('!H',checksum(frame[22:54]+struct.pack('!I3xB',size,6)+frame[54:54+size]))
            changed[index]['frame']=bytes(frame);variants.append((f'echo-{number}-{field}',changed,log))
    extra=[n for n,row in enumerate(rows) if len(row['frame'])==60 and row['frame'][12:14]==b'\x88\xcd' and row['frame'][19]%16 in (11,12)]
    require(len(extra)==16,'all original extra ownership fence request and reply mutation inputs')
    for number,index in enumerate(extra):
        variants.append((f'missing-ownership-fence-{number}',[deepcopy(r) for n,r in enumerate(rows) if n!=index],log))
        changed=deepcopy(rows);frame=bytearray(changed[index]['frame']);frame[0]^=1;changed[index]['frame']=bytes(frame)
        variants.append((f'foreign-ownership-fence-{number}',changed,log))
    for round_ in range(2):
        port=52000+lane*100+round_*10;wanted=bytes((lane*53+round_*31+2*17+n*7)&255 for n in range(16))
        sent=next(packet(rows[n]['frame']) for n in outputs if packet(rows[n]['frame'])['source']==port and packet(rows[n]['frame'])['data']==wanted)
        selected=[n for n in outgoing if packet(rows[n]['frame'])['source']==port and packet(rows[n]['frame'])['flags']==ACK and
            not packet(rows[n]['frame'])['data'] and packet(rows[n]['frame'])['seq']==(sent['seq']+16)&0xffffffff and
            packet(rows[n]['frame'])['ack']==(sent['ack']+16)&0xffffffff]
        require(selected,'actual withdrawn fallback echo acknowledgment mutation witness')
        variants.append((f'missing-fallback-ack-{round_}',[deepcopy(r) for n,r in enumerate(rows) if n not in selected],log))
        port=54000+lane*100+round_*10
        fin=next(n for n in tcp if packet(rows[n]['frame'])['target']==port and packet(rows[n]['frame'])['flags']==FIN|ACK)
        selected=[n for n in outgoing if n>fin and packet(rows[n]['frame'])['source']==port]
        require(len(selected)==1,'actual fresh companion final acknowledgment mutation witness')
        variants.append((f'missing-companion-final-ack-{round_}',[deepcopy(r) for n,r in enumerate(rows) if n not in selected],log))
    address_pattern=rf'^TCP6_ZONE_SOURCE_ROUTE_ADDRESS lane={lane} round=(\d+) phase=([a-z-]+) bytes=([a-f0-9]+)\r?$'
    address_rows=[]
    for match in re.finditer(address_pattern,log,re.M):
        data=bytes.fromhex(match[3]);attrs={};at=8
        while at<len(data):
            size,kind=struct.unpack_from('<HH',data,at);attrs[kind]=(at,size);at+=(size+3)&~3
        if 1 not in attrs:continue
        location,size=attrs[1];address=data[location+4:location+size]
        if address in (LOCAL,COMPANION):address_rows.append((match,data,attrs))
    require(len(address_rows)==22,'all exact scoped source ownership rows to corrupt')
    for number,(match,data,attrs) in enumerate(address_rows):
        for field in ('interface','prefix','scope','tentative','lifetime','address'):
            changed=bytearray(data)
            if field=='interface':changed[4]^=1
            elif field=='prefix':changed[1]^=1
            elif field=='scope':changed[3]^=1
            elif field=='tentative':
                if 8 in attrs:changed[attrs[8][0]+4]^=0x40
                else:changed[2]^=0x40
            elif field=='lifetime':changed[attrs[6][0]+4]^=1
            else:changed[attrs[1][0]+19]^=1
            start,end=match.span(3);text=log[:start]+changed.hex()+log[end:]
            variants.append((f'address-{number}-{field}',deepcopy(rows),text))
    for round_ in range(2):
        source=next(data for match,data,attrs in address_rows if int(match[1])==round_ and match[2]=='initial' and
            int.from_bytes(data[4:8],'little')==int(re.search(rf'^TCP6_ZONE_ROUTE_FIXTURE lane={lane} index=(\d+)',log,re.M)[1]) and
            data[attrs[1][0]+4:attrs[1][0]+attrs[1][1]]==LOCAL)
        for phase in ('withdrawn','fallback-withdrawn'):
            line=f'TCP6_ZONE_SOURCE_ROUTE_ADDRESS lane={lane} round={round_} phase={phase} bytes={source.hex()}\n'
            anchor=next(match.start() for match,data,attrs in address_rows if int(match[1])==round_ and match[2]==phase)
            variants.append((f'false-retained-owner-{round_}-{phase}',deepcopy(rows),log[:anchor]+line+log[anchor:]))
    pattern=rf'^TCP6_ZONE_SOURCE_ROUTE_BIND lane={lane} round=\d+ stage=\d+ zone=\d+ index=\d+ result=-?\d+ error=\d+\r?$'
    binds=list(re.finditer(pattern,log,re.M));require(len(binds)==16,'all actual source bind witness rows')
    for number,match in enumerate(binds):
        for field in ('stage','zone','index','result','error'):
            changed,count=re.subn(rf'({field}=)(-?\d+)',lambda m:m[1]+str(int(m[2])+1),match[0],count=1)
            require(count==1,'one actual fresh bind scalar to mutate')
            variants.append((f'bind-{number}-{field}',deepcopy(rows),log[:match.start()]+changed+log[match.end():]))
    pattern=rf'^TCP6_ZONE_SOURCE_ROUTE_COMPANION lane={lane} round=\d+ source=\d+ local_port=\d+ peer_port=\d+ closed=\d+\r?$'
    companions=list(re.finditer(pattern,log,re.M));require(len(companions)==2,'all actual fresh companion result rows')
    for number,match in enumerate(companions):
        for field in ('source','local_port','peer_port','closed'):
            changed,count=re.subn(rf'({field}=)(\d+)',lambda m:m[1]+str(int(m[2])+1),match[0],count=1)
            require(count==1,'one actual companion scalar to mutate')
            variants.append((f'companion-{number}-{field}',deepcopy(rows),log[:match.start()]+changed+log[match.end():]))
    for round_ in range(2):
        for phase in ('initial','withdrawn','fallback-withdrawn','input-restored','restored'):
            text,count=re.subn(rf'^TCP6_ZONE_SOURCE_ROUTE_ADDRESS lane={lane} round={round_} phase={phase} bytes=[a-f0-9]+\r?\n','',log,flags=re.M)
            require(count>0,'actual address inventory group to remove')
            variants.append((f'missing-inventory-{round_}-{phase}',deepcopy(rows),text))
    for origin in range(2):
        for round_ in range(2):
            for step in (11,12):
                phase=origin*64+round_*16+step
                text,count=re.subn(rf'^TCP6_ZONE_ROUTE_PHASE_PASS lane={lane} phase={phase}\r?\n','',log,count=1,flags=re.M)
                require(count==1,'actual logged ownership fence to remove')
                variants.append((f'missing-logged-ownership-{phase}',deepcopy(rows),text))
    variants.append(('completion',deepcopy(rows),log.replace(MARKER,'')))
    require(len(variants)==387,'complete combined source-route semantic control inventory')
    clocks=[json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()] if native else []
    if native:variants.extend((name,deepcopy(rows),log) for name in ('arrival-bound','capture-drop'))
    archive_path=output/(path.stem+'-damaged.zip');contexts=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('original/'+other.name,companion)
        for name,changed,text in variants:
            files={path.name:encode_capture(changed),'client.log':text.encode()}
            context=dict(name=name,capture_sha256=hashlib.sha256(files[path.name]).hexdigest(),
                log_sha256=hashlib.sha256(files['client.log']).hexdigest(),companion_sha256=hashlib.sha256(companion).hexdigest())
            if native:
                adjusted=[deepcopy(clocks[row['_clock_source']]) for row in changed]
                for n,(row,clock) in enumerate(zip(changed,adjusted)):
                    clock.update(frame=n,sha256=hashlib.sha256(row['frame']).hexdigest(),kernel_realtime_ns=row['ns'])
                if name=='arrival-bound':adjusted[0]['arrival_lower_ns']=adjusted[0]['receipt_monotonic_after_ns']+1
                encoded=('\n'.join(json.dumps(row) for row in adjusted)+'\n').encode();stats=deepcopy(statistics)
                stats.update(packets=len(changed),receipt_frames=len(changed),monotonic_receipts=path.with_suffix('.clocks.jsonl').name,
                    monotonic_receipts_sha256=hashlib.sha256(encoded).hexdigest())
                if name=='capture-drop':stats['dropped']=1
                context['statistics']=stats;files[path.with_suffix('.clocks.jsonl').name]=encoded
            files['context.json']=json.dumps(context).encode()
            for filename,body in files.items():archive.writestr(name+'/'+filename,body)
            contexts.append(dict(name=name,files=list(files)))
    rejected=[]
    with zipfile.ZipFile(archive_path) as archive:
        for item in contexts:
            with tempfile.TemporaryDirectory(prefix='axiom-source-route-control-') as temporary:
                case=Path(temporary)
                for filename in item['files']:(case/filename).write_bytes(archive.read(item['name']+'/'+filename))
                (case/other.name).write_bytes(archive.read('original/'+other.name))
                context=json.loads((case/'context.json').read_text())
                require(hashlib.sha256((case/path.name).read_bytes()).hexdigest()==context['capture_sha256'] and
                    hashlib.sha256((case/other.name).read_bytes()).hexdigest()==context['companion_sha256'] and
                    hashlib.sha256((case/'client.log').read_bytes()).hexdigest()==context['log_sha256'],
                    'exact freshly reopened source-route counterfeits and original companion bytes')
                try:verify(case/path.name,lane,(case/'client.log').read_text(),native,context.get('statistics'))
                except ValueError as error:
                    if item['name'] not in ('arrival-bound','capture-drop'):
                        require(not any(word in str(error) for word in ('checksum','arrival','clock','fingerprint')),
                            'source-route control reaches intended semantic predicate: '+item['name'])
                    rejected.append(dict(name=item['name'],reason=str(error)))
                else:raise ValueError('corrupt combined source-route evidence passed: '+item['name'])
    require(len(rejected)==(389 if native else 387) and path.read_bytes()==original and other.read_bytes()==companion,
        'every source-route control rejects and both original captures remain unchanged')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

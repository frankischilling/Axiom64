# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reconstruct simultaneous scoped streams and reset ownership."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile
from ipv4_expiry_capture import read_capture, encode_capture, checksum
from tcp6.capture import require

MASK = 0xffffffff
MARKER = 'TCP6_ISOLATION_PASS rounds=4 zones=2 bytes_each=32 quiet_ms=50'


def lower(row):
    return row.get('arrival_lower_ns',row['ns'])


def upper(row):
    return row.get('arrival_upper_ns',row['ns'])


def data(round_, lane, tag, size=32):
    return bytes((round_*53+lane*97+tag*29+n*7)%256 for n in range(size))


def decode(frame):
    require(len(frame)>=74 and frame[12:14]==b'\x86\xdd', 'complete original isolation IPv6 frame')
    ip=frame[14:]
    size=int.from_bytes(ip[4:6],'big')
    require(ip[:4]==b'\x60\0\0\0' and ip[6:8]==b'\x06\x40' and 20<=size<=len(ip)-40,
            'original isolation version, flow, protocol, hop and declared bounds')
    tcp=ip[40:40+size]
    fields=struct.unpack_from('!HHIIHHHH',tcp)
    header=(fields[4]>>12)*4
    require(20<=header<=size and not fields[4]&0x0e00 and not fields[7] and
            checksum(ip[8:40]+struct.pack('!I3xB',size,6)+tcp)==0,
            'original isolation TCP bounds, reserved bits and checksum')
    options=[]
    at=20
    while at<header:
        kind=tcp[at]
        if kind==0:
            require(not any(tcp[at:header]), 'zero original TCP option padding')
            break
        if kind==1:
            at+=1
            continue
        require(at+2<=header and 2<=tcp[at+1]<=header-at, 'bounded original TCP options')
        options.append((kind,tcp[at+2:at+tcp[at+1]]))
        at+=tcp[at+1]
    return dict(source=ip[8:24],target=ip[24:40],source_port=fields[0],target_port=fields[1],
        sequence=fields[2],ack=fields[3],flags=fields[4]&511,window=fields[5],
        options=options,data=tcp[header:])


def inspect(rows,lane,log,native=False):
    require(log.splitlines().count(MARKER)==1, 'one complete actual isolation client result')
    options=[tuple(map(int,m)) for m in re.findall(
        r'^TCP6_ISOLATION_OPTION_PASS family=(\d+) type=(\d+) queries=(\d+)\r?$',log,re.M)]
    require(options==[(family,type_,37) for family in (2,10) for type_ in (1,2,3)],
            'actual device query lengths, copy faults, shared bindings and all six transport families')
    names=[tuple(map(int,match)) for match in re.findall(
        r'^TCP6_ISOLATION_NAME_PASS round=(\d+) lane=(\d+) explicit_device=(\d+) index=(\d+) '
        r'local_scope=(\d+) peer_scope=(\d+) local_port=(\d+) peer_port=(\d+)\r?$',log,re.M)]
    require(len(names)==8 and [(r,n) for r,n,*_ in names]==[(r,n) for r in range(4) for n in range(2)],
            'actual duplicate scoped stream names in original open order')
    zones={}
    for round_,owner,bound,index,local_scope,peer_scope,local_port,peer_port in names:
        require(index>0 and local_scope==peer_scope==index and bound==round_//2 and
                local_port==49200+round_ and peer_port==49300+round_, 'actual scoped bind policy, names and ports')
        require(owner not in zones or zones[owner]==index, 'one actual interface index per isolation zone')
        zones[owner]=index
    require(zones[0]!=zones[1], 'simultaneous equal tuples have distinct actual zones')
    delivered=[tuple(map(int,m)) for m in re.findall(
        r'^TCP6_ISOLATION_DATA_PASS round=(\d+) lane=(\d+) tag=(\d+) bytes=32\r?$',log,re.M)]
    require(delivered==[(r,n,t) for r in range(4) for n,t in [(1,0),(0,0),(1-r%2,1)]],
            'actual second-zone-first delivery and post-reset surviving bytes')
    resets=[tuple(map(int,m)) for m in re.findall(
        r'^TCP6_ISOLATION_RESET_PASS round=(\d+) victim=(\d+) error=104 consumed=0 survivor_error=0\r?$',log,re.M)]
    require(resets==[(r,r%2) for r in range(4)], 'actual reset ownership and shared once-only error consumption')
    closes=[tuple(map(int,m)) for m in re.findall(
        r'^TCP6_ISOLATION_CLOSE_PASS round=(\d+) survivor=(\d+) eof=1\r?$',log,re.M)]
    require(closes==[(r,1-r%2) for r in range(4)], 'actual surviving-zone EOF and complete description release')
    phases=[0]+[r*8+s for r in range(4) for s in range(1,7)]
    phase_records=[tuple(map(int,m)) for m in re.findall(
        r'^TCP6_ISOLATION_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M)]
    require(len(phase_records)==50 and sorted(phase_records)==sorted((n,p) for n in range(2) for p in phases),
            'every original isolation client barrier completed once')
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane])
    peer=bytes([2,0x41,0x58,0x54,0x43,lane])
    control=bytes([2,73,80,54,lane,0])
    local,remote=ipaddress.IPv6Address('fe80::2').packed,ipaddress.IPv6Address('fe80::1').packed
    barriers={}
    tcp=[]
    for index,row in enumerate(rows):
        frame=row['frame']
        if not native and (0,0) not in barriers and frame[12:14]!=b'\x88\xc6':
            require(index<256 and frame[6:12]==guest, 'bounded original guest traffic before readiness')
            continue
        if frame[12:14]==b'\x88\xc6':
            require(len(frame)==60 and frame[14:19]==b'IP6I'+bytes([lane]) and
                    frame[19] in phases and frame[20] in (0,1) and not any(frame[21:]),
                    'original complete isolation control bytes')
            phase,answer=frame[19:21]
            require(frame[:12]==(guest+control if answer else control+guest) and (phase,answer) not in barriers,
                    'unique original control ownership')
            barriers[phase,answer]=dict(index=index,row=row)
        elif len(frame)>=54 and frame[12:14]==b'\x86\xdd' and frame[20]==6:
            value=decode(frame)
            outgoing=value['source']==local
            require(value['source']+value['target']==(local+remote if outgoing else remote+local) and
                    frame[:12]==(peer+guest if outgoing else guest+peer), 'original isolation address and interface ownership')
            round_=(value['source_port']-49200 if outgoing else value['target_port']-49200)
            require(0<=round_<4 and (value['target_port'] if outgoing else value['source_port'])==49300+round_,
                    'one original isolation generation owns the complete TCP tuple')
            tcp.append(dict(index=index,row=row,value=value,outgoing=outgoing,round=round_))
        elif len(frame)>=54 and frame[12:14]==b'\x86\xdd':
            ip=frame[14:]
            size=int.from_bytes(ip[4:6],'big')
            skip=8 if ip[6]==0 else 0
            require((ip[6]==58 or (native and ip[6]==0 and ip[40:48]==bytes.fromhex('3a00050200000100'))) and
                    skip+8<=size<=len(ip)-40 and not checksum(ip[8:40]+struct.pack('!I3xB',size-skip,58)+ip[40+skip:40+size]) and
                    ip[40+skip] in (133,135,136,143), 'bounded original isolation neighbor maintenance')
        else:
            require(not native and (0,0) not in barriers and index<256 and frame[6:12]==guest,
                    'bounded actual firmware prelude')
    require(set(barriers)=={(p,a) for p in phases for a in range(2)}, 'all original two-way isolation controls')
    ordered=[barriers[p,a]['index'] for p in phases for a in range(2)]
    require(ordered==sorted(ordered) and len(set(ordered))==50, 'ordered original isolation barriers')
    require(all(a['ns']<=b['ns'] for a,b in zip(rows,rows[1:])), 'unscaled original isolation capture order')
    durations=[]
    concurrency=[]
    for round_ in range(4):
        group=[x for x in tcp if x['round']==round_]
        outgoing=[x for x in group if x['outgoing']]
        incoming=[x for x in group if not x['outgoing']]
        syn=[x for x in outgoing if x['value']['flags']==2]
        synack=[x for x in incoming if x['value']['flags']==18]
        require(len(syn)==len(synack)==1 and not syn[0]['value']['data'] and not syn[0]['value']['ack'],
                'one actual original three-way handshake per zone and generation')
        client=(syn[0]['value']['sequence']+1)&MASK
        server=(0xfffffff1+round_*4096)&MASK
        offered=synack[0]['value']
        require(offered['sequence']==(server-1)&MASK and offered['ack']==client and
                offered['options']==[(2,b'\x02\x18')] and offered['window']==8192 and not offered['data'],
                'identical original peer initial sequence and MSS in both zones')
        handshake=[x for x in outgoing if x['value']['flags']==16 and not x['value']['data'] and
                   x['value']['sequence']==client and x['value']['ack']==server]
        base=round_*8
        require(handshake and syn[0]['index']<synack[0]['index']<handshake[0]['index']<barriers[base+1,1]['index'],
                'actual handshake completes before simultaneous-zone readiness')
        require(lower(barriers[base+1,1]['row'])-upper(barriers[base+1,0]['row'])>=50000000,
                'complete original simultaneous-open observation')
        durations.append(lower(barriers[base+1,1]['row'])-upper(barriers[base+1,0]['row']))
        victim=lane==round_%2
        payloads=[x for x in incoming if x['value']['data']]
        require(len(payloads)==(1 if victim else 2), 'exact initial and surviving-zone input count')
        for tag,item in enumerate(payloads):
            value=item['value']
            step=2 if tag==0 else 5
            require(value['flags']==24 and value['sequence']==(server+tag*32)&MASK and
                    value['ack']==(client+(32 if tag else 0))&MASK and value['window']==8192 and
                    not value['options'] and value['data']==data(round_,lane,tag),
                    'exact original payload reaches its actual interface zone')
            require(barriers[base+step,0]['index']<item['index']<barriers[base+step,1]['index'],
                    'original peer payload belongs to its own observation')
            duration=lower(barriers[base+step,1]['row'])-upper(item['row'])
            require(duration>=50000000, 'complete original isolation data observation')
            durations.append(duration)
            require(any(x['index']>item['index'] and x['index']<barriers[base+step,1]['index'] and
                        x['value']['ack']==(server+(tag+1)*32)&MASK for x in outgoing),
                    'actual owning zone acknowledges every original input byte')
        expected=data(round_,lane,2)+(b'' if victim else data(round_,lane,3,16))
        seen=bytearray(len(expected))
        for item in outgoing:
            value=item['value']
            require(value['flags'] in (2,16,24,17,25) and (not value['options'] or value['flags']==2),
                    'only original handshake, data, ACK and surviving close packets')
            if value['data']:
                offset=(value['sequence']-client)&MASK
                require(offset+len(value['data'])<=len(expected) and value['data']==expected[offset:offset+len(value['data'])],
                        'exact original outgoing bytes and wrapped sequence ownership')
                seen[offset:offset+len(value['data'])]=bytes([1])*len(value['data'])
                require(item['index']>barriers[base+(2 if offset<32 else 5),1]['index'],
                        'actual client output follows the matching complete input observation')
                if offset<32:
                    require(offset+len(value['data'])<=32 and item['index']<barriers[base+3,1]['index'],
                            'all original initial client bytes reach their zone before ownership checks')
            if value['flags']!=2:
                require(value['ack'] in {(server+n)&MASK for n in (0,32,64,65)} and
                        (value['sequence']-client)&MASK in (0,32,48,49),
                        'original sequence and acknowledgment space stays within its own stream')
        require(all(seen), 'every actual original client byte is captured')
        rst=[x for x in incoming if x['value']['flags']&4]
        fin=[x for x in incoming if x['value']['flags']&1]
        client_fin=[x for x in outgoing if x['value']['flags']&1]
        if victim:
            require(len(rst)==1 and not fin and not client_fin, 'only the selected zone receives one reset')
            item=rst[0]
            value=item['value']
            require(value['flags']==20 and value['sequence']==(server+32)&MASK and value['ack']==(client+32)&MASK and
                    not value['data'] and not value['window'] and not value['options'] and
                    barriers[base+4,0]['index']<item['index']<barriers[base+4,1]['index'],
                    'exact original reset bytes belong to the selected live zone')
            duration=lower(barriers[base+4,1]['row'])-upper(item['row'])
            require(duration>=50000000 and all(x['index']<item['index'] for x in outgoing),
                    'complete original reset observation with no response or surviving output in that zone')
            durations.append(duration)
        else:
            require(not rst and len(fin)==len(client_fin)==1, 'unaffected zone retains its real acknowledged close')
            terminal=fin[0]['value']
            require(terminal['flags']==17 and terminal['sequence']==(server+64)&MASK and terminal['ack']==(client+49)&MASK and
                    not terminal['data'] and terminal['window']==8192 and not terminal['options'],
                    'exact original surviving peer FIN')
            close=client_fin[0]
            require((close['value']['sequence']+len(close['value']['data']))&MASK==(client+48)&MASK and
                    close['index']<fin[0]['index'], 'actual original client half-close and final payload')
            require(any(x['index']>fin[0]['index'] and x['index']<barriers[base+6,1]['index'] and
                        x['value']['sequence']==(client+49)&MASK and x['value']['ack']==(server+65)&MASK and
                        x['value']['flags']==16 and not x['value']['data'] for x in outgoing),
                    'actual final ACK closes the surviving zone')
        for item in incoming:
            value=item['value']
            if value['flags']==16:
                require(not value['data'] and not value['options'] and value['window']==8192 and
                        (value['sequence'],value['ack']) in {((server+32)&MASK,(client+32)&MASK),((server+64)&MASK,(client+48)&MASK)},
                        'all original peer ACKs refer to actual client data in this zone')
            else:
                require(item in synack+payloads+rst+fin, 'no TCP input escapes its original isolation phase')
        concurrency.append(dict(round=round_,handshake_ns=handshake[0]['row']['ns'],probe_ns=payloads[0]['row']['ns']))
    return dict(passed=True,lane=lane,rounds=4,actual_streams=4,reset_zones=2,surviving_zones=2,
        peer_bytes=192,client_bytes=160,minimum_observation_ns=min(durations),
        interface_index=zones[lane],concurrency=concurrency,original_packet_times_not_rescaled=True)


def verify(path,lane,log,native=False,statistics=None):
    rows=read_capture(path)
    clock=None
    if native:
        from tcp6.observation import bind
        clock=bind(path,rows,statistics)
    result=inspect(rows,lane,log,native)
    other=inspect(read_capture(path.with_name(f'lane{1-lane}.pcap')),1-lane,log,native)
    for first,second in zip(result['concurrency'],other['concurrency']):
        require(first['round']==second['round'] and max(first['handshake_ns'],second['handshake_ns'])<
                min(first['probe_ns'],second['probe_ns']), 'both actual zones are established before either original data probe')
        zero,one=(first,second) if lane==0 else (second,first)
        require(one['probe_ns']<zero['probe_ns'], 'original second-zone-first data ordering across actual NIC captures')
    result.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),clock=clock)
    return result


def damaged(path,lane,log,native,output,statistics=None):
    rows=read_capture(path)
    if native:
        from tcp6.observation import bind
        bind(path,rows,statistics)
    inspect(rows,lane,log,native)
    original=path.read_bytes()
    packets=[n for n,row in enumerate(rows) if len(row['frame'])>=74 and row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]==6]
    incoming=[n for n in packets if rows[n]['frame'][6:12]==bytes([2,0x41,0x58,0x54,0x43,lane])]
    synack=next(n for n in incoming if decode(rows[n]['frame'])['flags']==18)
    payload=next(n for n in incoming if decode(rows[n]['frame'])['data'])
    rst=next(n for n in incoming if decode(rows[n]['frame'])['flags']==20)
    fin=next(n for n in incoming if decode(rows[n]['frame'])['flags']==17)
    ack=next(n for n,row in enumerate(rows) if row['frame'][12:14]==b'\x88\xc6' and row['frame'][19:21]==b'\x02\x01')
    variants={}
    for name,at in [('missing-handshake',synack),('missing-zone-data',payload),('missing-reset',rst),('missing-survivor-FIN',fin)]:
        variants[name]=[row for n,row in enumerate(rows) if n!=at],log
    def edit(name,at,change,repair=True):
        changed=copy.deepcopy(rows)
        frame=bytearray(changed[at]['frame'])
        change(frame)
        if repair:
            size=int.from_bytes(frame[18:20],'big')
            frame[70:72]=b'\0\0'
            frame[70:72]=struct.pack('!H',checksum(frame[22:54]+struct.pack('!I3xB',size,6)+frame[54:54+size]))
        changed[at]['frame']=bytes(frame)
        variants[name]=changed,log
    edit('bad-checksum',payload,lambda f:f.__setitem__(70,f[70]^1),False)
    edit('other-zone-MAC',payload,lambda f:f.__setitem__(5,0x10+1-lane))
    edit('other-zone-data',payload,lambda f:f.__setitem__(-1,f[-1]^1))
    edit('wrong-sequence',payload,lambda f:f.__setitem__(58,f[58]^1))
    edit('wrong-acknowledgment',payload,lambda f:f.__setitem__(62,f[62]^1))
    edit('wrong-source',payload,lambda f:f.__setitem__(23,f[23]^1))
    edit('wrong-port',payload,lambda f:f.__setitem__(55,f[55]^1))
    changed=copy.deepcopy(rows);changed.insert(rst,copy.deepcopy(changed[rst]));variants['repeated-reset']=changed,log
    changed=copy.deepcopy(rows)
    if native:
        changed[ack]['arrival_lower_ns']=upper(changed[payload])+1000000
        changed[ack]['arrival_upper_ns']=changed[ack]['arrival_lower_ns']
    else:
        changed[ack]['ns']=changed[payload]['ns']+1000000
    variants['short-observation']=changed,log
    variants['missing-name']=rows,re.sub(r'^TCP6_ISOLATION_NAME_PASS round=0 lane='+str(lane)+r' .*\r?\n','',log,count=1,flags=re.M)
    variants['false-scope']=rows,re.sub(r'(TCP6_ISOLATION_NAME_PASS round=0 lane='+str(lane)+r' .* peer_scope=)\d+',r'\g<1>0',log,count=1)
    variants['false-reset-owner']=rows,log.replace('TCP6_ISOLATION_RESET_PASS round=0 victim=0','TCP6_ISOLATION_RESET_PASS round=0 victim=1',1)
    variants['missing-EOF']=rows,re.sub(r'^TCP6_ISOLATION_CLOSE_PASS round=0 .*\r?\n','',log,count=1,flags=re.M)
    variants['missing-completion']=rows,log.replace(MARKER,'')
    variants['missing-device-query']=rows,re.sub(r'^TCP6_ISOLATION_OPTION_PASS family=2 type=1 .*\r?\n','',log,count=1,flags=re.M)
    variants['false-device-query']=rows,log.replace('TCP6_ISOLATION_OPTION_PASS family=2 type=1 queries=37','TCP6_ISOLATION_OPTION_PASS family=2 type=1 queries=36',1)
    archive_path=output/(path.stem+'-damaged.zip')
    rejected=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        for name,(changed,text) in variants.items():
            archive.writestr(name+'.pcap',encode_capture(changed))
            archive.writestr(name+'.log',text)
            archive.writestr(name+'.observations.json',json.dumps(dict(synthetic_damage=True,
                rows=[dict(index=n,sha256=hashlib.sha256(row['frame']).hexdigest(),ns=row['ns'],
                    lower_ns=lower(row),upper_ns=upper(row)) for n,row in enumerate(changed)])))
        with tempfile.TemporaryDirectory(prefix='axiom64-isolation-damage-') as temporary:
            for name in variants:
                saved=Path(temporary)/(name+'.pcap')
                saved.write_bytes(archive.read(name+'.pcap'))
                reopened=read_capture(saved)
                observation=json.loads(archive.read(name+'.observations.json'))
                require(observation['synthetic_damage'] and len(reopened)==len(observation['rows']), 'reopened isolation damage shape')
                for index,(row,item) in enumerate(zip(reopened,observation['rows'])):
                    require(item['index']==index and item['ns']//1000*1000==row['ns'] and
                            item['sha256']==hashlib.sha256(row['frame']).hexdigest(), 'reopened isolation damage bytes')
                    if native:
                        row.update(arrival_lower_ns=item['lower_ns'],arrival_upper_ns=item['upper_ns'])
                try:
                    inspect(reopened,lane,archive.read(name+'.log').decode(),native)
                except ValueError as error:
                    rejected.append(dict(name=name,reason=str(error)))
                else:
                    raise ValueError('reopened damaged TCP6 isolation evidence passed: '+name)
    require(len(rejected)==20 and path.read_bytes()==original, 'all altered isolation controls fail and original bytes remain')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

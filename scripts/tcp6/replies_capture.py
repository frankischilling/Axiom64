# SPDX-License-Identifier: GPL-3.0-or-later
"""Check original scoped/global reset conversations independently of the peer."""
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


def upper(row):
    return row.get('arrival_upper_ns',row['ns'])


def lower(row):
    return row.get('arrival_lower_ns',row['ns'])


def decode(frame):
    require(len(frame)>=74 and frame[12:14]==b'\x86\xdd', 'complete reply Ethernet IPv6 packet')
    ip=frame[14:]
    size=int.from_bytes(ip[4:6],'big')
    require(ip[:4]==b'\x60\0\0\0' and ip[6:8]==b'\x06\x40' and 20<=size<=len(ip)-40,
            'original reply IPv6 version, flow, protocol, hop and length')
    tcp=ip[40:40+size]
    fields=struct.unpack_from('!HHIIHHHH',tcp)
    require(fields[4]>>12==5 and not fields[4]&0x0e00 and not fields[7] and
            checksum(ip[8:40]+struct.pack('!I3xB',size,6)+tcp)==0,
            'exact original TCP header and pseudo-header checksum')
    return dict(source=ip[8:24],target=ip[24:40],source_port=fields[0],target_port=fields[1],
                sequence=fields[2],acknowledgment=fields[3],flags=fields[4]&511,window=fields[5],data=tcp[20:])


def inspect(rows,lane,log,native=False):
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane])
    peer=bytes([2,0x41,0x58,0x54,0x43,lane])
    control=bytes([2,73,80,54,lane,0])
    barriers={}
    tcp=[]
    for index,row in enumerate(rows):
        frame=row['frame']
        if frame[12:14]==b'\x88\xc5':
            require(len(frame)==60 and frame[14:19]==b'IP6R'+bytes([lane]) and
                    frame[19]<=40 and frame[20] in (0,1) and not any(frame[21:]),
                    'original complete reply control frame')
            phase,answer=frame[19:21]
            require(frame[:12]==(guest+control if answer else control+guest) and (phase,answer) not in barriers,
                    'unique reply control phase and actual interface ownership')
            barriers[phase,answer]=dict(index=index,row=row)
        elif len(frame)>=54 and frame[12:14]==b'\x86\xdd' and frame[20]==6:
            tcp.append(dict(index=index,row=row,value=decode(frame)))
    require(set(barriers)=={(phase,answer) for phase in range(41) for answer in range(2)},
            'all original setup, request and completion barriers')
    ordered=[barriers[phase,answer]['index'] for phase in range(41) for answer in range(2)]
    require(ordered==sorted(ordered) and len(set(ordered))==82, 'ordered original two-way reply barriers')
    marker='TCP6_REPLIES_PASS lanes=2 cases_each=20 quiet_ms=50'
    require(log.splitlines().count(marker)==1, 'one actual complete reply client result')
    pattern=r'^TCP6_REPLIES_CASE_PASS lane=(\d+) case=(\d+) scope=(link|global) listener=(\d+) index=(\d+)\r?$'
    records=[(int(a),int(b),c,int(d),int(e)) for a,b,c,d,e in re.findall(pattern,log,re.M)]
    require(len(records)==40 and [(a,b) for a,b,_,_,_ in records]==[(a,b) for a in range(2) for b in range(20)],
            'all actual client scope and listener observations in order')
    indices={a:{e for owner,_,_,_,e in records if owner==a} for a in range(2)}
    require(all(len(values)==1 and min(values)>0 for values in indices.values()) and indices[0]!=indices[1],
            'two distinct positive actual interface indices')
    selected=set()
    durations=[]
    for scenario in range(20):
        kind=scenario%10
        phase=scenario*2+1
        begin,ack,end=barriers[phase,0],barriers[phase,1],barriers[phase+1,1]
        found=[item for item in tcp if begin['index']<item['index']<end['index']]
        require(len(found)==(1 if kind==5 else 2), 'exact request and permitted response count')
        selected.update(item['index'] for item in found)
        request=found[0]
        prefix='fe80' if scenario<10 else f'2001:db8:{lane+1}'
        remote,local=ipaddress.IPv6Address(prefix+'::1').packed,ipaddress.IPv6Address(prefix+'::2').packed
        flags=(16,2,2,1,8,4,16,16,16,16)[kind]
        data=b'scope-syn' if kind==2 else b'scope-data' if kind==4 else b''
        sequence=(0xfffffff0+scenario*17+lane*4096)&0xffffffff
        acknowledgment=0x12340000+scenario*31+lane*4096
        expected=dict(source=remote,target=local,source_port=49360,target_port=49460,sequence=sequence,
                      acknowledgment=acknowledgment,flags=flags,window=8192,data=data)
        require(request['value']==expected and request['row']['frame'][:12]==guest+peer,
                'original exact incoming TCP bytes and receiving interface')
        duration=lower(ack['row'])-upper(request['row'])
        require(duration>=50000000 and request['index']<ack['index'],
                'complete original fifty-millisecond reply/silence observation')
        durations.append(duration)
        if kind!=5:
            response=found[1]
            expected=dict(source=local,target=remote,source_port=49460,target_port=49360,
                sequence=acknowledgment if flags&16 else 0,
                acknowledgment=0 if flags&16 else (sequence+len(data)+bool(flags&2)+bool(flags&1))&0xffffffff,
                flags=4 if flags&16 else 20,window=0,data=b'')
            require(response['value']==expected and response['row']['frame'][:12]==peer+guest and
                    request['index']<response['index']<ack['index'] and upper(response['row'])>=lower(request['row']),
                    'exact reset tuple, sequence, interface and causal order')
        actual=records[lane*20+scenario]
        require(actual[2]==('link' if scenario<10 else 'global') and actual[3]==(0 if kind<6 else kind-5),
                'actual closed-port or wildcard/scoped listener contract')
    require(selected=={item['index'] for item in tcp}, 'no TCP packet escapes its owned original scenario')
    return dict(passed=True,lane=lane,cases=20,actual_requests=20,actual_resets=18,silent_RST_inputs=2,
                distinct_interface_index=next(iter(indices[lane])),minimum_observation_ns=min(durations),
                original_packet_times_not_rescaled=True,scopes=['link','global'])


def verify(path,lane,log,native=False,statistics=None):
    rows=read_capture(path)
    clock=None
    if native:
        from tcp6.observation import bind
        clock=bind(path,rows,statistics)
    result=inspect(rows,lane,log,native)
    result.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),clock=clock)
    return result


def damaged(path,lane,log,native,output,statistics=None):
    rows=read_capture(path)
    if native:
        from tcp6.observation import bind
        bind(path,rows,statistics)
    inspect(rows,lane,log,native)
    original=path.read_bytes()
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane])
    outgoing=[n for n,row in enumerate(rows) if len(row['frame'])>=74 and row['frame'][12:14]==b'\x86\xdd' and
              row['frame'][20]==6 and row['frame'][6:12]==guest]
    response=outgoing[0]
    request=next(n for n,row in enumerate(rows) if len(row['frame'])>=74 and row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]==6)
    begin=next(n for n,row in enumerate(rows) if row['frame'][12:14]==b'\x88\xc5' and row['frame'][19:21]==b'\x0b\0')
    ack=next(n for n,row in enumerate(rows) if row['frame'][12:14]==b'\x88\xc5' and row['frame'][19:21]==b'\1\1')
    variants={}
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
    variants['missing-request']=[row for n,row in enumerate(rows) if n!=request],log
    variants['missing-reset']=[row for n,row in enumerate(rows) if n!=response],log
    changed=copy.deepcopy(rows);changed.insert(response,copy.deepcopy(changed[response]));variants['repeated-reset']=changed,log
    edit('checksum',response,lambda frame:frame.__setitem__(70,frame[70]^1),False)
    edit('other-zone-MAC',response,lambda frame:frame.__setitem__(5,1-lane))
    edit('wrong-sequence',response,lambda frame:frame.__setitem__(58,frame[58]^1))
    edit('wrong-acknowledgment',response,lambda frame:frame.__setitem__(65,1))
    edit('wrong-flags',response,lambda frame:frame.__setitem__(67,20))
    edit('wrong-source',response,lambda frame:frame.__setitem__(23,frame[23]^1))
    edit('wrong-port',response,lambda frame:frame.__setitem__(55,frame[55]^1))
    changed=copy.deepcopy(rows);changed.insert(begin+2,copy.deepcopy(changed[response]));variants['forbidden-reset-response']=changed,log
    changed=copy.deepcopy(rows)
    if native:
        changed[ack]['arrival_lower_ns']=changed[request]['arrival_upper_ns']+1000000
        changed[ack]['arrival_upper_ns']=changed[ack]['arrival_lower_ns']
    else:
        changed[ack]['ns']=changed[request]['ns']+1000000
    variants['short-observation']=changed,log
    row_pattern=r'^TCP6_REPLIES_CASE_PASS lane='+str(lane)+r' case=0 .*\r?\n'
    variants['missing-case-record']=rows,re.sub(row_pattern,'',log,count=1,flags=re.M)
    variants['false-scope']=rows,log.replace(f'TCP6_REPLIES_CASE_PASS lane={lane} case=0 scope=link',f'TCP6_REPLIES_CASE_PASS lane={lane} case=0 scope=global',1)
    variants['zero-index']=rows,re.sub(r'(TCP6_REPLIES_CASE_PASS lane='+str(lane)+r' case=0 .* index=)\d+',r'\g<1>0',log,count=1)
    variants['missing-completion']=rows,log.replace('TCP6_REPLIES_PASS lanes=2 cases_each=20 quiet_ms=50','')
    archive_path=output/(path.stem+'-damaged.zip')
    rejected=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        for name,(changed,text) in variants.items():
            archive.writestr(name+'.pcap',encode_capture(changed))
            archive.writestr(name+'.log',text)
            archive.writestr(name+'.observations.json',json.dumps(dict(synthetic_damage=True,
                rows=[dict(index=n,sha256=hashlib.sha256(row['frame']).hexdigest(),ns=row['ns'],
                    lower_ns=lower(row),upper_ns=upper(row)) for n,row in enumerate(changed)])))
        with tempfile.TemporaryDirectory(prefix='axiom64-reply-damage-') as temporary:
            for name in variants:
                saved=Path(temporary)/(name+'.pcap')
                saved.write_bytes(archive.read(name+'.pcap'))
                reopened=read_capture(saved)
                observation=json.loads(archive.read(name+'.observations.json'))
                require(observation['synthetic_damage'] and len(reopened)==len(observation['rows']), 'reopened altered observation shape')
                for index,(row,item) in enumerate(zip(reopened,observation['rows'])):
                    require(item['index']==index and item['ns']//1000*1000==row['ns'] and
                            item['sha256']==hashlib.sha256(row['frame']).hexdigest(), 'reopened altered original packet bytes')
                    if native:
                        row.update(arrival_lower_ns=item['lower_ns'],arrival_upper_ns=item['upper_ns'])
                try:
                    inspect(reopened,lane,archive.read(name+'.log').decode(),native)
                except ValueError as error:
                    rejected.append(dict(name=name,reason=str(error)))
                else:
                    raise ValueError('reopened damaged TCP6 reply evidence passed: '+name)
    require(len(rejected)==16 and path.read_bytes()==original, 'all altered reply controls fail and original bytes remain')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

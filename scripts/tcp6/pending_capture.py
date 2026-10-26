# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct pending-source TCP sequences and withdrawal causality from PCAP."""
import hashlib
import ipaddress
import re
from ipv4_expiry_capture import read_capture
from tcp6.capture import require
from tcp6.observation import bind
from tcp6.peer import packet
from tcp_fault_peer import ACK,FIN,SYN

MARKER='TCP6_PENDING_SOURCE_PASS lanes=2 rounds_each=4 flows_each=8'
def add(value,delta=1):return (value+delta)&0xffffffff

def verify(path,lane,log,native=False,statistics=None):
    require(log.splitlines().count(MARKER)==1,'one actual pending source program completion')
    phases=[tuple(map(int,row)) for row in re.findall(
        r'^TCP6_PENDING_SOURCE_PHASE_PASS lane=(\d+) phase=(\d+)\r?$',log,re.M)]
    expected=[(0,0),(1,0)]+[(n,r*16+s) for n in range(2) for r in range(4) for s in range(1,6)]
    require(phases==expected,'all original ordered pending source barriers')
    withdrawn=[tuple(map(int,row)) for row in re.findall(
        r'^TCP6_PENDING_WITHDRAWN lane=(\d+) round=(\d+) bind_result=(-?\d+) bind_errno=(\d+) error=(\d+)\r?$',log,re.M)]
    require(withdrawn==[(n,r,-1,99,0) for n in range(2) for r in range(4)],
        'every fresh bind rejects absent source with zero pending description error')
    connected=[tuple(map(int,row)) for row in re.findall(
        r'^TCP6_PENDING_CONNECT lane=(\d+) round=(\d+) result=(-?\d+) error=(\d+)\r?$',log,re.M)]
    require(connected==[(n,r,-1,115) for n in range(2) for r in range(3)],
        'all actual asynchronous source connects')
    established=[tuple(map(int,row)) for row in re.findall(
        r'^TCP6_PENDING_ESTABLISHED lane=(\d+) round=(\d+) error=(\d+)\r?$',log,re.M)]
    require(established==[(n,r,0) for n in range(2) for r in range(4)],
        'every retained source completes its actual handshake')
    rows=read_capture(path);clock=bind(path,rows,statistics) if native else None
    guest=bytes([0x52,0x54,0,0x12,0x34,0x10+lane]);peer=bytes([2,0x41,0x58,0x54,0x43,lane])
    remote=ipaddress.IPv6Address(f'2001:db8:{lane+1}::1').packed
    controls=bytes([2,73,80,54,lane,0]);barriers={};streams={(r,c):[] for r in range(4) for c in (False,True)}
    phases=[0]+[r*16+s for r in range(4) for s in range(1,6)]
    for index,row in enumerate(rows):
        frame=row['frame']
        if len(frame)>=21 and frame[12:14]==b'\x88\xca':
            phase,answer=frame[19:21]
            require(len(frame)==60 and phase in phases and answer in (0,1) and
                (phase,answer) not in barriers and frame[:12]==(guest+controls if answer else controls+guest) and
                frame[14:19]==b'IP6P'+bytes([lane]) and not any(frame[21:]),'unique owned pending source barrier')
            barriers[phase,answer]=index
        if not (len(frame)>=74 and frame[12:14]==b'\x86\xdd' and frame[20]==6):continue
        value=packet(frame);outgoing=frame[6:12]==guest
        require(frame[:12]==(peer+guest if outgoing else guest+peer) and not value['flags']&4,
            'actual pending source TCP owner and no reset')
        matches=[]
        for r,c in streams:
            a=(51200 if c else 51000)+r*10+lane;b=(51300 if c else 51100)+r*10+lane
            if (value['source'],value['target'])==((a,b) if outgoing else (b,a)):matches.append((r,c))
        require(len(matches)==1,'every actual pending source full port tuple')
        r,c=matches[0];local=ipaddress.IPv6Address(f'2001:db8:{lane+1}::{3 if c else 2}').packed
        require(value['source_ip']+value['target_ip']==(local+remote if outgoing else remote+local),
            'every actual prebound/pending/fresh full IPv6 address')
        require((frame[21],(int.from_bytes(frame[14:18],'big')>>20)&255)==(64,0),
            'fixed pending source wire header controls')
        streams[r,c].append(dict(index=index,value=value,outgoing=outgoing,row=row))
    require(set(barriers)=={(p,a) for p in phases for a in (0,1)},'complete pending source barrier pairs')
    observations=[]
    for (r,c),flow in streams.items():
        base=r*16;passive=r==3 and not c
        syn=[x for x in flow if x['outgoing'] and x['value']['flags']==(SYN|ACK if passive else SYN)]
        handshake=[x for x in flow if not x['outgoing'] and x['value']['flags']==(SYN if passive else SYN|ACK)]
        data=[x for x in flow if x['outgoing'] and x['value']['data']]
        echo=[x for x in flow if not x['outgoing'] and x['value']['data']]
        fin=[x for x in flow if x['outgoing'] and x['value']['flags']&FIN]
        peerfin=[x for x in flow if not x['outgoing'] and x['value']['flags']&FIN]
        require(len(handshake)==len(data)==len(echo)==len(fin)==len(peerfin)==1 and
            (len(syn)==1 if c else len(syn)>=2),
            'complete actual pending/retry or fresh handshake, data, echo and FINs')
        origin=syn[0]['value']['seq'];client=add(origin);server=add(handshake[0]['value']['seq'])
        require(all(x['value']['seq']==origin and not x['value']['data'] and
            x['value']['ack']==(server if passive else 0) for x in syn),'same original SYN sequence on every actual retry')
        require(handshake[0]['value']['ack']==(0 if passive else client),
            'exact actual handshake peer acknowledgment')
        expected=bytes((lane*53+r*31+c*17+n*7)&255 for n in range(16))
        require(data[0]['value']['data']==echo[0]['value']['data']==expected and
            data[0]['value']['seq']==client and data[0]['value']['ack']==server and
            echo[0]['value']['seq']==server and echo[0]['value']['ack']==add(client,16),
            'actual exact bytes and sequence after completed pending handshake')
        require(fin[0]['value']['seq']==add(client,16) and fin[0]['value']['ack']==add(server,16) and
            peerfin[0]['value']['seq']==add(server,16) and peerfin[0]['value']['ack']==add(client,17),
            'exact actual pending source half-close sequences')
        final=[x for x in flow if x['outgoing'] and x['index']>peerfin[0]['index']]
        require(len(final)==1 and final[0]['value']['flags']==ACK and not final[0]['value']['data'] and
            final[0]['value']['seq']==add(client,17) and final[0]['value']['ack']==add(server,17),
            'actual pending source final ACK')
        require(syn[-1]['index']<data[0]['index']<echo[0]['index']<fin[0]['index']<peerfin[0]['index']<final[0]['index']<barriers[base+5,0],
            'actual full stream closes before final release barrier')
        retry_lower=None
        if not c:
            companion=streams[r,True]
            companion_final=companion[-1]['index']
            require(companion_final<syn[-1]['index']<barriers[base+3,1]<barriers[base+4,0],
                'real fresh companion proves usable route before actual withdrawn-source retry')
            require(all(x['outgoing'] for x in flow if barriers[base+2,1]<x['index']<barriers[base+4,0]),
                'no TCP input delivered to pending source while its local route is absent')
            release=[x for x in flow if not x['outgoing'] and x['index']>syn[-1]['index']][0]
            require(barriers[base+4,0]<release['index']<barriers[base+4,1],
                'pending handshake input follows explicit source restoration')
            if not r:
                require(companion_final<barriers[base+2,0]<barriers[base+2,1]<syn[0]['index'],
                    'prebound connect starts after actual withdrawal and fresh companion close')
            else:
                require(barriers[base+1,1]<syn[0]['index']<barriers[base+2,1]<companion[0]['index'],
                    'active or passive first SYN precedes withdrawal and fresh source connection')
            first,last=syn[0]['row'],syn[1]['row']
            retry_lower=(last['arrival_lower_ns']-first['arrival_upper_ns']) if native else last['ns']-first['ns']
            require(retry_lower>=850000000,'original natural handshake retry exceeds established 850ms wire lower bound')
        observations.append(dict(round=r,companion=c,passive=passive,handshake_count=len(syn),
            first_handshake=syn[0]['index'],last_handshake=syn[-1]['index'],final_ack=final[0]['index'],
            retry_lower_ns=retry_lower))
    return dict(passed=True,global_pending_source_withdrawal=True,full_source_route_device_expiry_acceptance=False,
        lane=lane,actual_flows=8,actual_pending_handshakes=4,actual_output_blocks=8,
        observations=observations,clock=clock,sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def damaged(path,lane,log,native,output,statistics=None):
    from copy import deepcopy
    from pathlib import Path
    import json
    import struct
    import tempfile
    import zipfile
    from ipv4_expiry_capture import encode_capture
    from tcp_fault_peer import checksum
    actual=verify(path,lane,log,native,statistics)
    original=path.read_bytes();rows=read_capture(path);variants=[]
    clocks=([json.loads(line) for line in path.with_suffix('.clocks.jsonl').read_text().splitlines()]
            if native else [])
    def alter(label,index,offset,value):
        changed=deepcopy(rows);frame=bytearray(changed[index]['frame'])
        frame[offset:offset+len(value)]=value
        length=int.from_bytes(frame[18:20],'big');frame[70:72]=bytes(2)
        frame[70:72]=struct.pack('!H',checksum(frame[22:54]+struct.pack('!I3xB',length,6)+frame[54:54+length]))
        changed[index]['frame']=bytes(frame);variants.append((label,changed,log,None))
    for item in actual['observations']:
        if item['companion']:continue
        r=item['round'];first,last=item['first_handshake'],item['last_handshake']
        companion=next(x for x in actual['observations'] if x['round']==r and x['companion'])
        alter(f'r{r}-retained-source',last,37,b'\3')
        alter(f'r{r}-retry-sequence',last,58,add(int.from_bytes(rows[last]['frame'][58:62],'big')).to_bytes(4,'big'))
        changed=deepcopy(rows);changed.pop(last);variants.append((f'r{r}-missing-retry',changed,log,None))
        changed=deepcopy(rows)
        if not native:changed[last]['ns']=changed[first]['ns']+100000000
        variants.append((f'r{r}-short-retry',changed,log,(first,last)))
        alter(f'r{r}-wire-class',last,15,bytes([rows[last]['frame'][15]^16]))
        final=item['final_ack']
        alter(f'r{r}-close-sequence',final,58,add(int.from_bytes(rows[final]['frame'][58:62],'big')).to_bytes(4,'big'))
        alter(f'r{r}-fresh-source',companion['first_handshake'],37,b'\2')
        release=next(n for n in range(last+1,len(rows)) if len(rows[n]['frame'])>=74 and
            rows[n]['frame'][12:14]==b'\x86\xdd' and rows[n]['frame'][20]==6 and
            rows[n]['frame'][6:12]!=bytes([0x52,0x54,0,0x12,0x34,0x10+lane]))
        barrier=next(n for n,row in enumerate(rows) if row['frame'][12:14]==b'\x88\xca' and
            row['frame'][19:21]==bytes([r*16+4,0]))
        changed=deepcopy(rows);changed.insert(barrier,changed.pop(release))
        variants.append((f'r{r}-early-handshake-input',changed,log,None))
        changed=deepcopy(rows);frame=bytearray(changed[barrier]['frame']);frame[19]=r*16+3
        changed[barrier]['frame']=bytes(frame);variants.append((f'r{r}-restore-barrier',changed,log,None))
    for label,text in (('fresh-bind-result',log.replace('bind_errno=99','bind_errno=0',1)),
        ('connect-error',log.replace('result=-1 error=115','result=-1 error=0',1)),
        ('completion',log.replace(MARKER,''))):variants.append((label,deepcopy(rows),text,None))
    require(len(variants)==39,'complete pending source semantic-control inventory')
    if native:
        variants.extend([(label,deepcopy(rows),log,None) for label in ('arrival-bound','capture-drop')])
    archive_path=output/(path.stem+'-damaged.zip');contexts=[]
    with zipfile.ZipFile(archive_path,'x',zipfile.ZIP_DEFLATED) as archive:
        for label,changed,text,short in variants:
            payloads={'lane.pcap':encode_capture(changed),'client.log':text.encode()}
            context=dict(label=label,capture_sha256=hashlib.sha256(payloads['lane.pcap']).hexdigest(),
                log_sha256=hashlib.sha256(payloads['client.log']).hexdigest(),native=native)
            if native:
                # Rebind serialized counterfeits so each reaches the source,
                # sequence, causality or timer predicate under examination.
                adjusted=deepcopy(clocks[:len(changed)])
                for n,(row,clock) in enumerate(zip(changed,adjusted)):
                    clock.update(frame=n,sha256=hashlib.sha256(row['frame']).hexdigest(),kernel_realtime_ns=row['ns'])
                if short is not None:
                    first,last=short;start=adjusted[first]['receipt_monotonic_after_ns']
                    # Fabricate ordered brackets for intervening maintenance
                    # frames as well, so this counterfeit reaches the RTO check.
                    for n in range(first+1,last+1):
                        value=start+100000000*(n-first)//(last-first)
                        adjusted[n].update(arrival_lower_ns=value,receipt_monotonic_ns=value,receipt_monotonic_after_ns=value)
                if label=='arrival-bound':adjusted[0]['arrival_lower_ns']=adjusted[0]['receipt_monotonic_after_ns']+1
                encoded=('\n'.join(json.dumps(row) for row in adjusted)+'\n').encode()
                stats=deepcopy(statistics)
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
            with tempfile.TemporaryDirectory(prefix='tcp6-pending-control-') as temporary:
                case=Path(temporary)
                for name in item['files']:(case/name).write_bytes(archive.read(item['label']+'/'+name))
                context=json.loads((case/'context.json').read_text())
                require(hashlib.sha256((case/'lane.pcap').read_bytes()).hexdigest()==context['capture_sha256'] and
                    hashlib.sha256((case/'client.log').read_bytes()).hexdigest()==context['log_sha256'],
                    'actual reopened pending source control bytes')
                try:verify(case/'lane.pcap',lane,(case/'client.log').read_text(),native,context.get('statistics'))
                except ValueError as error:
                    if item['label'] not in ('arrival-bound','capture-drop'):
                        require(not any(word in str(error) for word in ('checksum','arrival','clock','fingerprint')),
                            'pending source corruption reaches its semantic predicate')
                    rejected.append(dict(name=item['label'],reason=str(error)))
                else:raise ValueError('damaged pending source evidence passed: '+item['label'])
    require(len(rejected)==(41 if native else 39) and path.read_bytes()==original,
        'every pending source control rejected without changing actual evidence')
    return dict(passed=True,rejected=rejected,archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest())

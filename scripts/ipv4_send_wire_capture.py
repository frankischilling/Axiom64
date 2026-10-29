# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct held routes and copy ordering from complete original physical captures."""
import json
import struct
from ipv4_receive_wire_packets import pcap, checksum
from ipv4_receive_wire_records import require, unique
from ipv4_send_wire_records import primary, target, waiting_scenario
from tcp_capture_clock import bind_native_clock


def identity(address):
    lane,case = ((address >> 8) & 255)-1,(address & 255)-1
    if address >> 16 == 0xc612 and lane in (0,1) and 50 <= case < 68:
        return lane,case
    lane,case = divmod(address-0xcb007101,64)
    return (lane,case) if lane in (0,1) and 0 <= case < 50 else None


def lifetime_retired(case):
    mode,mutation = divmod(case-50,3)
    return mode < 4 and mutation != 0


def relevant(frame):
    if frame[12:14] == b'\x88\xb9':
        return True
    if frame[12:14] == b'\x08\0' and len(frame) >= 34:
        return identity(int.from_bytes(frame[30:34],'big')) is not None
    if frame[12:14] == b'\x08\x06' and len(frame) >= 42:
        return any(identity(int.from_bytes(frame[at:at+4],'big')) is not None for at in (28,38))
    return False


def body(origin, case, phase, kind, number, size):
    data = bytearray((n*19+case*7+origin*31+phase*11+kind*13)&255 for n in range(size))
    data[:9] = b'SWIR'+bytes((origin,case,phase,kind,number))
    return bytes(data)


def read_lane(directory, lane, metadata):
    raw = pcap((directory/f'lane{lane}.pcap').read_bytes())
    selected = [dict(stamp=timestamp//1000,frame=frame,monotonic_ns=timestamp)
                for timestamp,frame in raw if relevant(frame)]
    clock = None
    if metadata['native']:
        clock = bind_native_clock(directory/f'lane{lane}.pcap',selected,metadata['capture_statistics'][lane])
    observed = json.loads((directory/f'lane{lane}-frames.json').read_text(),object_pairs_hook=unique)
    require(all(set(row)=={'monotonic_ns','direction','data'} and row['direction'] in ('guest','peer') and
        type(row['monotonic_ns']) is int and row['monotonic_ns']>0 for row in observed) and
        all(a['monotonic_ns']<=b['monotonic_ns'] for a,b in zip(observed,observed[1:])),
        'complete original host transport observations')
    guest,peer=bytes.fromhex(f'52540012341{lane}'),bytes.fromhex(f'02415852580{lane}')
    for direction,source in (('guest',guest),('peer',peer)):
        physical=[row['frame'] for row in selected if row['frame'][6:12]==source]
        transport=[bytes.fromhex(row['data']) for row in observed if row['direction']==direction and relevant(bytes.fromhex(row['data']))]
        require(physical==transport,'independent physical FIFO equals every original transport frame in this direction')
    require(all(row['frame'][6:12] in (guest,peer) for row in selected),'original physical source identities')
    return selected,clock


def verify(directory, metadata, records):
    captures=[read_lane(directory,lane,metadata) for lane in range(2)]
    data,barriers,arp={}, {}, []
    for lane,(rows,clock) in enumerate(captures):
        guest,peer=bytes.fromhex(f'52540012341{lane}'),bytes.fromhex(f'02415852580{lane}')
        for row in rows:
            frame,when=row['frame'],row['monotonic_ns']
            if frame[12:14]==b'\x88\xb9':
                require(len(frame)==60 and frame[14:18]==b'SCTL' and frame[18]==lane and
                    frame[19]<68 and frame[20] in (0,1,2) and frame[21] in (0,1), 'complete physical ownership barrier')
                case,phase,reply=frame[19:22]
                require(frame[:12]==(guest+peer if reply else peer+guest) and
                    frame[22:]==bytes((n*17+case*7+lane*31+phase)&255 for n in range(22,60)),
                    'complete original physical barrier bytes and direction')
                key=lane,case,phase,reply
                require(key not in barriers,'unique physical barrier')
                barriers[key]=when
                continue
            if frame[12:14]==b'\x08\x06':
                require(42<=len(frame)<=60 and frame[14:20]==b'\0\x01\x08\0\x06\x04' and
                    frame[42:]==bytes(len(frame)-42),'actual complete ARP envelope')
                operation=int.from_bytes(frame[20:22],'big')
                require(operation in (1,2),'actual ARP request or reply')
                owned=identity(int.from_bytes(frame[38:42] if operation==1 else frame[28:32],'big'))
                require(owned is not None,'actual owned ARP destination')
                if operation==1:
                    require(frame[:12]==b'\xff'*6+guest and frame[22:28]==guest and
                        frame[32:38]==bytes(6),'actual unresolved-neighbor request')
                else:
                    require(frame[:12]==guest+peer and frame[22:28]==peer and frame[32:38]==guest,
                        'actual owned neighbor release reply')
                arp.append(dict(lane=lane,identity=owned,operation=operation,time=when,
                    sender=int.from_bytes(frame[28:32],'big'),destination=int.from_bytes(frame[38:42],'big')))
                continue
            require(frame[12:14]==b'\x08\0' and frame[:12]==peer+guest,'actual data next-hop and selected adapter')
            ip=frame[14:]
            require(len(ip)>=20 and ip[0]==0x45 and checksum(ip[:20])==0 and
                int.from_bytes(ip[2:4],'big')==len(ip) and not int.from_bytes(ip[6:8],'big')&0x3fff,
                'complete original unfragmented IP datagram and checksum')
            origin,case=identity(int.from_bytes(ip[16:20],'big'))
            segment=ip[20:]
            require(len(segment)>=17 and segment[8:12]==b'SWIR','actual full owned payload token')
            app=segment[8:]
            actual_origin,actual_case,phase,kind,number=app[4:9]
            expected_kind=case//12 if case<36 else case-41 if case in (42,43) else 0
            require((actual_origin,actual_case,kind)==(origin,case,expected_kind) and
                app==body(origin,case,phase,kind,number,64 if case<36 else 1100),
                'complete original payload at its required copy point')
            expected_lane,source,ttl,tos=origin,primary(origin),63,34
            if case<36:
                require(phase in (0,1) and number==0,'ordinary selected/default payload identity')
                selected=case%6
                if phase==0 and selected:
                    expected_lane=origin^1 if selected in (2,3,5) else origin
                    source=primary(origin)+40 if selected in (1,3) else primary(origin^1)+40 if selected==4 else primary(expected_lane)
                    ttl,tos=37,184
            elif case>=50:
                mode,mutation=divmod(case-50,3)
                source=0xc6120102+origin*256 if mode in (2,3) else primary(origin)
                if phase==2:
                    expected_lane,source=origin^1,primary(origin^1)
                elif phase==3:
                    require(number==0 and (metadata['native'] or not lifetime_retired(case)),
                        'a retired FIB selection cannot emit a guest datagram')
                    ttl,tos=37,184
                elif phase==1:
                    require(number==0,'one fresh lifetime baseline')
                    ttl,tos=11,8
                    if mutation==0 and mode!=5:
                        expected_lane=origin^1
                    if mode&1:
                        source=0xc6120102+origin*256 if mode==3 else primary(origin)
                    elif expected_lane!=origin:
                        source=primary(origin^1)
                    else:
                        source=primary(origin) if mode==0 and mutation==1 else 0xc6120102+origin*256
                else:
                    raise ValueError('known physical lifetime payload phase')
            elif case not in (42,43):
                if phase==1:
                    expected_lane,source,ttl,tos=origin^1,primary(origin^1),11,8
                elif phase in (3,4):
                    require(waiting_scenario(case) not in (3,5) and phase==(4 if waiting_scenario(case)==2 else 3) and number==0 and
                        (case>=44 or metadata['native']),
                        'failed or interrupted send cannot emit a datagram')
                    source=primary(origin)+(40 if waiting_scenario(case)==1 else 0)
                    ttl,tos=37,184
                else:
                    require(phase==2,'actual waiting fill')
            else:
                require(phase in (1,2),'raw refused request emits no datagram')
                if phase==1:
                    ttl,tos=11,8
            require(lane==expected_lane and int.from_bytes(ip[12:16],'big')==source and
                (ip[8],ip[1],ip[9])==(ttl,tos,1 if kind==2 else 17),'actual retained route/source/interface/TTL/TOS')
            if kind==2:
                require(segment[:2]==b'\xfd\0' and segment[4:8]==b'\x6d\x53\0\0' and checksum(segment)==0,
                    'complete actual raw ICMP payload and checksum')
            else:
                sport,dport,size,check=struct.unpack('!HHHH',segment[:8])
                require(dport==49157 and size==len(segment) and 0<sport<=65535 and
                    (kind==0 or sport==51000+origin*64+case),'actual UDP ports and declared length')
                if kind==1:
                    require(check==0,'caller-supplied raw UDP checksum bytes')
                else:
                    require(check and checksum(ip[12:20]+struct.pack('!BBH',0,17,len(segment))+segment)==0,
                        'actual UDP pseudo-header checksum uses retained source')
            key=origin,case,phase,number
            require(key not in data,'unique original owned data packet')
            data[key]=when
    wanted_barriers={(lane,case,phase,reply) for lane in range(2) for case in range(68)
                     for phase in range(3) for reply in range(2)}
    require(set(barriers)==wanted_barriers,'all816 physical ownership barriers including the original600')
    # Native kernels differ in the lifetime of cached output after final FIB
    # retirement. Observe that policy explicitly; every successful retired case
    # must agree. Guest output must follow final-owner discard semantics.
    retirement = set()
    for lane in range(2):
        for case in (36,37,38,40):
            retirement.add((lane,case,4 if case==38 else 3,0) in data)
    require(len(retirement)==1 and (metadata['native'] or retirement=={False}),
        'consistent measured native retirement policy or required guest final-owner discard')
    retired_emits = True in retirement
    lifetime_policies={}
    for mode in range(4):
        for mutation in (1,2):
            case=50+mode*3+mutation
            policies={(lane,case,3,0) in data for lane in range(2)}
            require(len(policies)==1 and (metadata['native'] or policies=={False}),
                'consistent measured native lifetime policy or required guest FIB retirement')
            lifetime_policies[str(mode)+':'+str(mutation)]='retained' if True in policies else 'discarded'
    wanted_data=set()
    for lane in range(2):
        previous=None
        for case in range(68):
            stamps=[barriers[lane,case,phase,reply] for phase in range(3) for reply in range(2)]
            require(all(a<=b for a,b in zip(stamps,stamps[1:])) and
                (previous is None or previous<=stamps[0]) and
                all(stamps[phase*2+1]-stamps[phase*2]<=3000000000 for phase in range(3)),
                'actual ordered requests/acknowledgments under original three-second bounds')
            previous=stamps[-1]
            if case>=50:
                mode,mutation=divmod(case-50,3)
                emits=not lifetime_retired(case) or lifetime_policies[str(mode)+':'+str(mutation)]=='retained'
                phases=(1,3) if emits else (1,)
            else:
                phases=(0,1) if case<36 else (1,) if case in (39,41,42,43,47,49) or (case<42 and not retired_emits) else (1,4 if waiting_scenario(case)==2 else 3)
            for phase in phases:
                key=lane,case,phase,0
                wanted_data.add(key)
                require(key in data,'all original selected/default data packets')
                # A later send can still await ARP when its barrier request
                # reaches the peer. The acknowledgment owns completed output.
                lower,upper=(stamps[3],stamps[5]) if phase==1 else (stamps[1],stamps[4] if case<42 or (case>=50 and lifetime_retired(case)) else stamps[3])
                require(lower<=data[key]<=upper,
                    'selected data before release ACK; baseline follows release: '+str((key,lower,data[key],upper)))
            if 36<=case<42 or (case>=50 and lifetime_retired(case)):
                require(stamps[4]-stamps[3]>=3000000000,
                    'full physical three-second retired-output observation before later baseline completion')
            if case>=36:
                for number in range(records['fills'][lane,case]):
                    key=lane,case,2,number
                    wanted_data.add(key)
                    require(key in data and stamps[1]<=data[key]<=stamps[5], 'every actual retained fill packet survives release')
    require(set(data)==wanted_data,'complete exact physical packets, without rejected or extra datagrams')
    require(arp,'actual ARP withheld and released')
    for reply in [row for row in arp if row['operation']==2]:
        origin,case=reply['identity']
        require(barriers[origin,case,1,0]<=reply['time']<=barriers[origin,case,2,1],
            'neighbor release follows explicit mutation barrier')
        require(any(request['operation']==1 and request['identity']==reply['identity'] and
            request['lane']==reply['lane'] and request['sender']==reply['destination'] and
            request['destination']==reply['sender'] and request['time']<=reply['time'] for request in arp),
            'ARP reply owns an original pending request')
    return dict(data_packets=len(data),physical_barriers=len(barriers),arp_frames=len(arp),
        retired_route_policy='retained' if retired_emits else 'discarded',
        lifetime_route_policies=lifetime_policies,
        native_clocks=[row[1] for row in captures] if metadata['native'] else None,
        capture_frames=[len(row[0]) for row in captures])

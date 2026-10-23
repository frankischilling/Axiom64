# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen router captures without using the live peer's state or counters."""
import hashlib
import ipaddress
import re
import struct

from tcp_capture_clock import bind_native_clock, microseconds, raw_records


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def checksum(data):
    data += bytes(len(data) % 2)
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def qemu_records(path):
    with path.open('rb') as stream:
        header=stream.read(24)
        require(len(header)==24 and header[:4] in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4'),
                'QEMU Ethernet PCAP header')
        endian='<' if header[:4]==b'\xd4\xc3\xb2\xa1' else '>'
        major,minor,_,_,snap,link=struct.unpack_from(endian+'HHIIII',header,4)
        require((major,minor,link)==(2,4,1) and 1514<=snap<=65536,
                'QEMU Ethernet PCAP format and 65536-byte snapshot bound')
        count=0
        while True:
            encoded=stream.read(16)
            if not encoded:
                break
            require(len(encoded)==16,'complete QEMU Ethernet record')
            seconds,micros,size,original=struct.unpack(endian+'IIII',encoded)
            require(micros<1000000 and 14<=size==original<=min(snap,1518),
                    'complete bounded QEMU Ethernet frame')
            frame=stream.read(size)
            require(len(frame)==size,'complete original QEMU Ethernet bytes')
            yield dict(stamp=seconds*1000000+micros,frame=frame)
            count+=1
        require(count,'nonempty actual QEMU Ethernet capture')


def inspect(path, lane, text, native=False, statistics=None, linux_vm=False):
    linux = native or linux_vm
    guest = bytes.fromhex(f'5254001234{16 + lane:02x}')
    peer = bytes([2, 0x49, 0x50, 0x36, lane, 1])
    control = bytes([2, ord('I'), ord('P'), ord('6'), lane, 0])
    identifier = bytes([guest[0] ^ 2]) + guest[1:3] + b'\xff\xfe' + guest[3:]
    link = ipaddress.IPv6Address('fe80::').packed[:8] + identifier
    router = ipaddress.IPv6Address('fe80::42').packed
    prefixes = {kind:ipaddress.IPv6Address(f'2001:db8:{0x40 + lane:x}:{kind:x}::').packed
                for kind in (1,2,3,4)}
    generated = {kind:prefix[:8] + identifier for kind,prefix in prefixes.items()}
    distant = ipaddress.IPv6Address('2001:db8:ffff::42').packed
    remote = prefixes[2][:-1] + b'\x42'
    retry_target = prefixes[1][:-1] + b'\x44'
    neighbor_retries, neighbor_replies = [], []
    other_guest = bytes.fromhex(f'5254001234{17 - lane:02x}')
    other_identifier = bytes([other_guest[0] ^ 2]) + other_guest[1:3] + b'\xff\xfe' + other_guest[3:]
    other_prefix = ipaddress.IPv6Address(f'2001:db8:{0x41 - lane:x}:1::').packed
    other_generated = other_prefix[:8] + other_identifier
    other_retry = other_prefix[:-1] + b'\x44'
    routed_requests, routed_replies = [], []

    def routed_payload(incoming, phase):
        return b'RARC' + bytes([incoming, phase]) + bytes(at * 11 + phase for at in range(6, 16))

    rows = list(raw_records(path) if native else qemu_records(path))
    requests, replies, bad, advertisements, dad, rs, udp, echoes, timed = [], [], [], [], [], [], [], [], []
    active, mld, prelude = False, 0, 0
    for number,row in enumerate(rows):
        frame = row['frame']
        if frame[12:14] == b'\x88\xbf':
            require(len(frame)==60 and frame[14:19]==b'IP6R'+bytes([lane]), 'captured router barrier fields')
            phase = frame[19]
            if frame[6:12] == guest:
                require(frame[:6]==control and phase==len(requests) and not any(frame[20:]),
                        'captured ordered router client requests')
                requests.append((phase,row)); active=True
            else:
                require(frame[:12]==guest+control and phase==len(replies) and frame[20]==1 and
                        not any(frame[21:]), 'captured ordered router peer acknowledgments')
                replies.append((phase,row))
            timed.append(row)
            continue
        if not active:
            prelude += 1
            require(prelude<=256, 'bounded retained router firmware prelude')
            continue
        require(len(frame)>=54 and frame[12:14]==b'\x86\xdd' and frame[14]>>4==6,
                'captured IPv6 router workload')
        length,protocol,hops = struct.unpack_from('!HBB',frame,18)
        require(len(frame)>=54+length,'complete captured router IPv6 payload')
        source,destination,body = frame[22:38],frame[38:54],frame[54:54+length]
        outgoing = frame[6:12] == guest
        require(outgoing or frame[6:12]==peer,'captured router interface MAC ownership')
        if linux and protocol==0 and len(body)>=16 and body[:2]==bytes([58,0]):
            payload=body[8:]
            require(outgoing and hops==1 and destination[0]==255 and payload[0] in (131,132,143) and
                    not checksum(source+destination+struct.pack('!I3xB',len(payload),58)+payload),
                    'captured native multicast report')
            mld += 1
            continue
        timed.append(row)
        fragmented = protocol==44
        if fragmented:
            require(not outgoing and body[:8]==bytes([58,0,0,0,0,0,0,1]),
                    'captured original forbidden atomic ND fragment')
            body,protocol = body[8:],58
        require(protocol in (17,58) and len(body)>=8,'captured router upper-layer protocol')
        check = checksum(source+destination+struct.pack('!I3xB',len(body),protocol)+body)
        if protocol==58 and body[0]==134:
            require(not outgoing and len(body)>=16 and destination==ipaddress.IPv6Address('ff02::1').packed,
                    'captured advertisement direction and destination')
            options, invalid, at = [], None, 16
            while at<len(body):
                if len(body)-at<2:
                    invalid='tail'; break
                size=body[at+1]*8
                if not size:
                    invalid='zero'; break
                if size>len(body)-at:
                    invalid='bounds'; break
                options.append(body[at:at+size]);at+=size
            source_options=[option for option in options if option[0]==1]
            kind = (8 if fragmented else 0 if source!=router else 1 if hops!=255 else
                    2 if body[1] else 3 if check else 6 if source_options and len(source_options[0])!=8 else
                    7 if source_options and source_options[0][2]&1 else
                    5 if invalid=='zero' else 4 if invalid else None)
            if kind is not None:
                bad.append(kind)
                require(body[4]==17 and int.from_bytes(body[6:8],'big')==60,
                        'captured malformed cohort identity')
                continue
            require(not invalid and len(source_options)==1 and source_options[0]==b'\x01\x01'+peer,
                    'captured valid advertisement option chain')
            mtu=[int.from_bytes(option[4:8],'big') for option in options if option[0]==5]
            pios=[option for option in options if option[0]==3]
            position=len(advertisements)
            expected=[(0,48,1400,None,None),(4,61,1300,8,2),(0,61,1300,0,0),
                      (0,61,1300,10000,6000),(0,61,1300,0,0),
                      (0,61,1300,0,0),(0,61,1300,100,60),(0,61,1300,0,0),(0,61,1300,100,60),
                      (0,61,1300,None,None),(0,41+lane*10,1300,None,None)]
            require(position<len(expected),'bounded valid advertisement count')
            lifetime,hop,mtu_value,valid,preferred=expected[position]
            require((int.from_bytes(body[6:8],'big'),body[4],mtu)==(lifetime,hop,[mtu_value]),
                    'captured exact router lifetime, hop limit and IPv6 MTU')
            require(int.from_bytes(body[8:12],'big')==0 and
                    int.from_bytes(body[12:16],'big')==(2000+lane*1000 if position==9 else 0),
                    'captured original per-interface advertised neighbor timer')
            require(len(pios)==(0 if valid is None else 4),'captured complete independent prefix flag cohort')
            for option,(kind_number,flags) in zip(pios,((1,0xc0),(2,0x80),(3,0x40),(4,0))):
                require(len(option)==32 and option[1:4]==bytes([4,64,flags]) and
                        int.from_bytes(option[4:8],'big')==valid and
                        int.from_bytes(option[8:12],'big')==preferred and option[16:]==prefixes[kind_number],
                        'captured prefix flags, lifetimes and network identity')
            advertisements.append(row)
            continue
        require(not fragmented and not check,'captured valid kernel/peer upper-layer checksum')
        if not outgoing and ((protocol==58 and body[0]==128) or
                             (protocol==17 and body[8:12]==b'RARC')):
            phase=20 if protocol==58 else 21
            require(source==other_retry and destination==generated[1] and hops==64 and
                    frame[:6]==guest and len(body)==24 and body[8:]==routed_payload(lane,phase),
                    'captured original cross-interface reply input')
            if phase==20:
                require(body[1]==0 and body[4:8]==struct.pack('!HH',0x5241,lane),
                        'captured original cross-interface echo identifier')
            else:
                require(body[:6]==struct.pack('!HHH',48000+lane,48999,24) and body[6:8]!=bytes(2),
                        'captured original closed-port datagram')
            routed_requests.append((phase,row))
            continue
        if outgoing and protocol==58 and body[0] in (129,1):
            phase=20 if body[0]==129 else 21
            require(source==other_generated and destination==retry_target and frame[:6]==peer and
                    hops==41+lane*10, 'captured routed kernel reply uses outgoing learned hop limit')
            if phase==20:
                require(len(body)==24 and body[1]==0 and body[4:8]==struct.pack('!HH',0x5241,1-lane) and
                        body[8:]==routed_payload(1-lane,phase),
                        'captured routed echo retains original identifier and payload')
            else:
                quoted=bytearray(struct.pack('!HHHH',48001-lane,48999,24,0)+routed_payload(1-lane,phase))
                struct.pack_into('!H',quoted,6,checksum(retry_target+other_generated+
                    struct.pack('!I3xB',len(quoted),17)+quoted) or 65535)
                original=struct.pack('!IHBB',6<<28,len(quoted),17,64)+retry_target+other_generated+quoted
                require(body[:2]==b'\x01\x04' and body[4:8]==bytes(4) and body[8:]==original,
                        'captured routed error retains the complete original datagram quote')
            routed_replies.append((phase,row))
            continue
        if protocol==17:
            require(len(body)==24 and body[6:8]!=bytes(2) and int.from_bytes(body[4:6],'big')==24,
                    'captured original UDP length/checksum fields')
            phase=body[13]
            expected=b'RATR'+bytes([lane,phase])+bytes(at*7+phase for at in range(6,16))
            wanted_source=link if phase==2 else generated[1]
            wanted_destination=router if phase==2 else distant if phase==3 else retry_target if phase==5 else remote
            require(phase in (2,3,4,5) and body[8:]==expected,'captured exact router application payload')
            if outgoing:
                require(body[:4]==struct.pack('!HH',47000+lane,47001) and source==wanted_source and
                        destination==wanted_destination and hops==(48 if phase==2 else 61) and frame[:6]==peer,
                        'captured guest generated source and learned-hop UDP')
                udp.append((phase,row))
            else:
                require(body[:4]==struct.pack('!HH',47001,47000+lane) and source==wanted_destination and
                        destination==wanted_source and hops==64 and frame[:6]==guest,
                        'captured exact independent UDP response')
                echoes.append((phase,row))
        elif outgoing and body[0]==133:
            require(hops==255 and source==link and destination==ipaddress.IPv6Address('ff02::2').packed and
                    body[:2]==bytes([133,0]) and body[4:]==bytes(4)+b'\x01\x01'+guest,
                    'captured ready-source router solicitation')
            rs.append(row)
        elif outgoing and body[0]==135 and source==bytes(16):
            target=body[8:24]
            extra=linux and target==ipaddress.IPv6Address(f'2001:db8:{0x40+lane:x}:6b::').packed[:8]+identifier
            require(target in (link,generated[1],generated[3]) or extra,'captured configured DAD target')
            require(hops==255 and len(body)==32 and body[24:26]==b'\x0e\x01' and
                    destination==b'\xff\x02'+bytes(9)+b'\x01\xff'+target[-3:] and
                    frame[:6]==b'\x33\x33\xff'+target[-3:],'captured enhanced DAD nonce and group')
            dad.append((target,row))
        elif outgoing and body[0]==135:
            require(hops==255 and body[8:24] in (router,remote,retry_target) and source in
                    (link,generated[1],generated[3]) and body[24:]==b'\x01\x01'+guest,
                    'captured owned next-hop neighbor query')
            if body[8:24]==retry_target:
                require(source==generated[1] and len(body)==32 and body[:2]==bytes([135,0]) and
                        body[4:8]==bytes(4) and destination==b'\xff\x02'+bytes(9)+b'\x01\xff'+retry_target[-3:] and
                        frame[:6]==b'\x33\x33\xff'+retry_target[-3:],
                        'captured retry source, target and solicited-node group')
                neighbor_retries.append(row)
        else:
            require(not outgoing and body[0]==136 and hops==255 and source in (router,remote,retry_target) and
                    body[8:24]==source and body[24:]==b'\x02\x01'+peer,
                    'captured peer neighbor response')
            if source==retry_target:
                require(destination==generated[1] and body[4:8]==b'\x60\0\0\0',
                        'captured solicited delayed neighbor advertisement')
                neighbor_replies.append(row)
    require([phase for phase,_ in requests]==list(range(23)) and
            [phase for phase,_ in replies]==list(range(23)),'captured complete router phase union')
    require(sorted(bad)==list(range(9)) and len(advertisements)==11,'every original malformed/policy and valid advertisement is retained')
    require([phase for phase,_ in udp]==[2,3,4,5] and [phase for phase,_ in echoes]==[2,3,4,5],
            'captured complete generated-source UDP exchange union')
    require(len(neighbor_retries)==2 and len(neighbor_replies)==1,
            'captured initial/retry solicitations and one delayed answer')
    require([phase for phase,_ in routed_requests]==[20,21] and
            [phase for phase,_ in routed_replies]==[20,21],
            'captured complete cross-interface echo and error union')
    counts={target.hex():sum(value==target for value,_ in dad) for target in (link,generated[1],generated[3])}
    require(counts=={link.hex():1,generated[1].hex():2,generated[3].hex():2},'captured initial and post-expiry DAD counts')
    require(len(rs)>=(1 if linux else 2),'captured router solicitations')
    require(text.splitlines().count(f'IPV6_ROUTER_MAC_POLICY lane={lane} installed={int(linux)}')==1,
            'actual client records the measured multicast source-link-layer policy')
    replacement_lines = [line for line in text.splitlines()
                         if line.startswith(f'IPV6_ROUTER_REPLACEMENT lane={lane} ')]
    require(len(replacement_lines)==6,'six source-bound replacement and recreation state observations')
    for line,expected in zip(replacement_lines,(('replaced',0x82,4294967295,4294967295),
                                              ('zero',0xa2,0,7200),('finite',0x82,60,7200),
                                              ('readded',0x82,4294967295,4294967295),
                                              ('readd-zero',0xa2,0,7200),('readd-finite',0x82,60,7200))):
        match=re.fullmatch(r'IPV6_ROUTER_REPLACEMENT lane=([01]) phase=(replaced|zero|finite|readded|readd-zero|readd-finite) '
            r'flags=([0-9a-f]+) preferred=(\d+) valid=(\d+) prefix_routes=1 prefix_permanent=1',line)
        require(match is not None,'complete actual replacement flags, cache and connected-route result')
        phase,flags,preferred,valid=match.group(2),int(match.group(3),16),int(match.group(4)),int(match.group(5))
        require((phase,flags)==expected[:2] and
                expected[2]-(2 if expected[2]==60 else 0)<=preferred<=expected[2] and
                expected[3]-(0 if expected[3]==4294967295 else 2)<=valid<=expected[3],
                'actual replacement preserves Linux metadata and protected lifetimes')
    clock,clock_error=None,None
    if native:
        try:
            clock=bind_native_clock(path,timed,statistics)
        except ValueError as error:
            clock_error=str(error)
    timing_error=None
    if not native or clock is not None:
        try:
            retry_interval=microseconds(neighbor_retries[1])-microseconds(neighbor_retries[0])
            expected=(2000+lane*1000)*1000
            require(expected-20000<=retry_interval<=expected+500000,
                    'captured learned neighbor timer preserves the distinct two/three-second intervals')
            require(microseconds(replies[17][1])<=microseconds(neighbor_retries[0]) and
                    microseconds(neighbor_retries[1])<=microseconds(neighbor_replies[0])<=microseconds(udp[3][1])<=microseconds(echoes[3][1])<=microseconds(requests[18][1]),
                    'captured timer admission, resolution, UDP and completion order')
            for phase,row in routed_requests:
                require(microseconds(replies[19][1])<=microseconds(row)<=microseconds(replies[phase][1]),
                        'captured cross-interface input and acknowledgment ordering')
            for _,row in routed_replies:
                require(microseconds(advertisements[10])<=microseconds(row)<=microseconds(requests[22][1]),
                        'captured learned hop update precedes routed reply and completion')
            require(microseconds(requests[5][1])-microseconds(advertisements[1])>=3980000,
                    'captured default-router expiry keeps four real seconds')
            require(microseconds(requests[6][1])-microseconds(advertisements[1])>=7980000,
                    'captured finite-address expiry keeps eight real seconds')
            if not linux:
                require(3590000<=microseconds(rs[1])-microseconds(rs[0])<=4410000,
                        'captured RFC 7559 interval keeps four seconds with ten-percent jitter')
            for target in (generated[1],generated[3]):
                first=next(row for value,row in dad if value==target)
                require(microseconds(udp[1][1])-microseconds(first)>=980000,
                        'captured autonomous address completes real DAD before traffic')
        except ValueError as error:
            timing_error=str(error)
    passed=clock_error is None and timing_error is None
    return dict(passed=passed,content_passed=True,lane=lane,frames=len(rows),prelude=prelude,
                malformed_and_policy_cases=sorted(bad),valid_advertisements=len(advertisements),
                generated_UDP_pairs=4,replacement_states=6,neighbor_retransmissions=2,
                retransmit_milliseconds=2000+lane*1000,dad_counts=counts,solicitations=len(rs),native_MLD=mld,
                routed_replies=2,routed_reply_hop_limit=41+lane*10,
                native_clock=clock,native_clock_error=clock_error,timing_error=timing_error,
                original_timestamps_preserved=True,sha256=hashlib.sha256(path.read_bytes()).hexdigest())

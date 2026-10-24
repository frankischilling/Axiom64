# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen ownership packets and serial inventories without the live peer's state."""
import hashlib
import ipaddress
import re
import struct

from ipv6_router_capture import checksum, qemu_records, require
from ipv6_dad_policy import retain_exhausted_prefix
from tcp_capture_clock import bind_native_clock, microseconds, raw_records


def plan(group):
    result = [(0,0,int(group == 'lifecycle'))]
    def snapshot(case,stage,count):
        result.extend([(2,case,stage)] * count)
        result.append((3,case,stage))
    for case in range(1,5) if group == 'global' else range(5,10):
        result.append((1,case,0 if case == 2 else 1 if case >= 8 else 2))
        if case <= 4:
            for stage in (0,1,2):snapshot(case,stage,1)
            if case == 2:
                result.append((6,case,0));snapshot(case,5,0)
            else:
                result.extend([(4,case,0),(9,case,0),(10,case,0)])
                snapshot(case,3,1 if case == 4 else 2)
                result.append((6,case,0));snapshot(case,4,1)
                result.append((6,case,1));snapshot(case,5,0)
        else:
            if case == 6:result.append((5,case,0))
            result.extend((4,case,trial) for trial in range(4 if case == 7 else 1))
            if case in (5,6):result.extend([(9,case,0),(10,case,0)])
            snapshot(case,3,{5:2,6:3,7:4}.get(case,0))
            if case >= 8:
                snapshot(case,4,1);snapshot(case,5,1)
        result.append((7,case,0))
    result.append((8,0,0))
    return result


def inspect(path,lane,text,group,native=False,statistics=None,native_kernel_release=None):
    require(group in ('global','lifecycle') and lane in (0,1), 'known ownership group and NIC')
    retain = retain_exhausted_prefix(native_kernel_release) if native else False
    guest=bytes.fromhex(f'5254001234{16+lane:02x}')
    peer=bytes([2,0x49,0x50,0x36,lane,1]);control=bytes([2,0x49,0x50,0x36,lane,0])
    identifier=bytes([guest[0]^2])+guest[1:3]+b'\xff\xfe'+guest[3:]
    link=ipaddress.IPv6Address('fe80::').packed[:8]+identifier
    router=ipaddress.IPv6Address('fe80::42').packed;all_nodes=ipaddress.IPv6Address('ff02::1').packed
    cases=list(range(1,5) if group=='global' else range(5,10))
    prefixes={case:ipaddress.IPv6Address(f'2001:db8:{0x40+lane:x}:{case:x}::').packed for case in cases}
    rows=list(raw_records(path) if native else qemu_records(path))
    expected=plan(group);requests=[];replies=[];probes={case:[] for case in cases}
    conflicts={case:[] for case in cases};advertisements={case:[] for case in cases}
    snapshots={};summaries={};timed=[];firmware=[];mld=0;active=0
    for index,row in enumerate(rows):
        row['index']=index;f=row['frame']
        if f[12:14]==b'\x88\xc3':
            require(len(f)==60 and f[14:19]==b'IP6O'+bytes([lane]), 'captured complete ownership control')
            phase=f[19]
            if f[6:12]==guest:
                require(f[:6]==control and phase==len(requests) and phase<len(expected) and
                        tuple(f[20:23])==expected[phase] and f[23]==(int(retain) if phase==0 else 0),
                        'captured exact ordered ownership plan and pinned policy')
                kind,case,stage=expected[phase];flags,preferred,valid=struct.unpack_from('!III',f,24)
                stamp=int.from_bytes(f[52:60],'big')
                require(stamp>0 and (not requests or stamp>=requests[-1]['guest_ns']),
                        'actual nondecreasing guest monotonic observations')
                value=dict(row=row,kind=kind,case=case,stage=stage,flags=flags,preferred=preferred,
                           valid=valid,target=f[36:52],guest_ns=stamp)
                if kind in (0,1,5,7,8):require(f[24:52]==bytes(28),'captured non-address controls have no invented metadata')
                if kind==1:active=case
                elif kind in (2,3,4,6,9,10):require(case==active,'captured metadata belongs to current ownership case')
                if kind==2:snapshots.setdefault((case,stage),[]).append(value)
                if kind==3:
                    require((case,stage) not in summaries,'one actual summary per snapshot')
                    summaries[case,stage]=value
                requests.append(value)
            else:
                require(f[:12]==guest+control and phase==len(replies) and f[20:]==b'\x01'+bytes(39),
                        'captured complete ordered ownership ACK')
                replies.append(row)
            timed.append(row);continue
        if not requests:
            require(f[6:12]==guest and len(firmware)<256,'bounded original firmware traffic on actual adapter')
            firmware.append(hashlib.sha256(f).hexdigest());continue
        require(active in cases and len(f)>=62 and f[12:14]==b'\x86\xdd' and f[14]>>4==6 and
                len(f)==54+int.from_bytes(f[18:20],'big'), 'captured complete original ownership IPv6 frame')
        source,destination,body=f[22:38],f[38:54],f[54:]
        outgoing=f[6:12]==guest
        require(outgoing or f[6:12]==peer,'captured actual adapter and peer ownership')
        if f[20]==0:
            require(native and outgoing and mld<512 and f[21]==1 and len(body)>=16 and
                    body[:8]==b'\x3a\0\x05\x02\0\0\x01\0' and
                    f[:6]==b'\x33\x33'+destination[-4:] and
                    (source==bytes(16) or ipaddress.IPv6Address(source).is_link_local),
                    'captured complete native multicast router alert and source')
            payload=body[8:]
            require(payload[1]==0 and not checksum(source+destination+struct.pack('!I3xB',len(payload),58)+payload),
                    'captured complete native multicast checksum')
            if payload[0] in (131,132):
                require(len(payload)==24 and payload[4:8]==bytes(4) and payload[8]==255 and
                        destination==(payload[8:24] if payload[0]==131 else ipaddress.IPv6Address('ff02::2').packed),
                        'captured complete multicast report or leave')
            else:
                require(payload[0]==143 and payload[4:6]==bytes(2) and destination==ipaddress.IPv6Address('ff02::16').packed,
                        'captured complete MLDv2 header')
                count=int.from_bytes(payload[6:8],'big');at=8
                require(0<count<=32,'bounded captured multicast records')
                for _ in range(count):
                    require(at+20<=len(payload) and 1<=payload[at]<=6 and payload[at+1]==0 and payload[at+4]==255,
                            'captured complete multicast group record')
                    at+=20+16*int.from_bytes(payload[at+2:at+4],'big')
                require(at==len(payload),'captured complete multicast group framing')
            mld+=1;continue
        timed.append(row)
        require(f[20:22]==b'\x3a\xff' and body[1]==0 and
                not checksum(source+destination+struct.pack('!I3xB',len(body),58)+body),
                'captured complete ownership neighbor-discovery checksum, code and hop limit')
        if body[0]==134:
            preferred,valid=(60,100) if active==2 else (30,60)
            require(not outgoing and active<=4 and source==router and destination==all_nodes and
                    f[:6]==b'\x33\x33\0\0\0\x01' and len(body)==64 and
                    body[4:16]==bytes([64,0])+bytes(10) and body[16:24]==b'\x01\x01'+peer and
                    body[24:56]==struct.pack('!BBBBIII16s',3,4,64,0xc0,valid,preferred,0,prefixes[active]) and
                    body[56:]==struct.pack('!BBHI',5,1,0,1500), 'captured exact original ownership advertisement')
            advertisements[active].append(row);continue
        require(body[0] in (135,136) and len(body)==32,'captured complete selected DAD probe or conflict')
        target=body[8:24]
        if body[0]==135:
            require(outgoing and source==bytes(16) and body[4:8]==bytes(4) and body[24:26]==b'\x0e\x01' and
                    destination==b'\xff\x02'+bytes(9)+b'\x01\xff'+target[-3:] and
                    f[:6]==b'\x33\x33\xff'+target[-3:], 'captured exact enhanced DAD nonce and multicast target')
            probes[active].append(dict(row=row,target=target,nonce=body[26:32]))
        else:
            require(not outgoing and body[4:8]==struct.pack('!I',0x20000000) and body[24:]==b'\x02\x01'+peer and
                    source==router and destination==all_nodes and f[:6]==b'\x33\x33\0\0\0\1',
                    'captured complete selected duplicate-address advertisement')
            conflicts[active].append(dict(row=row,target=target))
    clock=bind_native_clock(path,timed,statistics) if native else None
    require(len(requests)==len(replies)==len(expected),'all captured ownership operations have complete ACKs')
    require(all(a['row']['index']<b['index'] and (i+1==len(requests) or b['index']<requests[i+1]['row']['index'])
                for i,(a,b) in enumerate(zip(requests,replies))), 'causal exact request and ACK ordering')
    serial=re.findall(r'^IPV6_OWNER_CONTROL lane='+str(lane)+r' phase=(\d+) kind=(\d+) case=(\d+) stage=(\d+) '
        r'flags=([0-9a-f]+) preferred=(\d+) valid=(\d+) target=([0-9a-f]{32}) observed_ns=(\d+)\r?$',text,re.M)
    require(len(serial)==len(expected),'all original ownership serial observations retained')
    for phase,(fields,value) in enumerate(zip(serial,requests)):
        actual=tuple(map(int,fields[:4]))+(int(fields[4],16),int(fields[5]),int(fields[6]),bytes.fromhex(fields[7]),int(fields[8]))
        require(actual==(phase,value['kind'],value['case'],value['stage'],value['flags'],value['preferred'],value['valid'],value['target'],value['guest_ns']),
                'every original serial field equals its captured actual query metadata')
    marker=f'IPV6_OWNER_PASS adapters=2 group={group} cases_each={len(cases)} quiet_seconds=4'
    require(text.splitlines().count(marker)==1 and not any(word in text for word in ('IPV6_OWNER_FAIL','PANIC:','FAULT pid=')),
            'one successful actual ownership client with no kernel fault')
    def values(case,stage):
        rows=snapshots.get((case,stage),[]);summary=summaries[case,stage]
        require(summary['flags']==len(rows) and summary['valid']==0 and len({row['target'] for row in rows})==len(rows),
                'complete unique actual address inventory and exact summary')
        expected_prefix=ipaddress.IPv6Address('fe80::').packed if (stage==0 or 5<=case<=7) else prefixes[case]
        require(summary['target']==expected_prefix and all(row['target'][:8]==expected_prefix[:8] for row in rows),
                'actual summary and all address owners use the selected prefix')
        return rows
    def one(case,kind):
        found=[row for row in requests if row['case']==case and row['kind']==kind]
        require(len(found)==1,'one selected captured lifecycle operation')
        return found[0]
    def exact(value,flags,preferred,valid):
        require((value['flags'],value['preferred'],value['valid'])==(flags,preferred,valid),
                'captured exact raw address flags and cache lifetimes')
    inf=0xffffffff;reports=[]
    for case in cases:
        case_probes=probes[case];case_conflicts=conflicts[case]
        require(len(case_probes)=={1:3,2:2,3:2,4:3,5:2,6:3,7:4,8:2,9:1}[case] and
                len(case_conflicts)==(0 if case==2 else 4 if case==7 else 1),
                'exact actual probe/conflict counts including quiet and NODAD cases')
        begin=one(case,1);end=one(case,7)
        require(all(begin['row']['index']<entry['row']['index']<end['row']['index'] for entry in [*case_probes,*case_conflicts]),
                'all actual DAD traffic belongs inside its complete case')
        selected=[row for row in requests if row['kind']==4 and row['case']==case]
        for request,conflict in zip(selected,case_conflicts):
            require(request['target']==conflict['target'] and request['row']['index']<conflict['row']['index']<replies[requests.index(request)]['index'],
                    'actual conflict is queued after queried metadata and before its ACK')
            preceding=[probe for probe in case_probes if probe['target']==request['target'] and probe['row']['index']<conflict['row']['index']]
            require(len(preceding)==1,'one actual matching DAD probe before conflict injection')
            flags={1:0x8c0,3:0x8c2,4:0x840}.get(case,0x8c0 if case<=7 else 0x40)
            preferred,valid=(6,10) if case==4 else (2,8) if case>=8 else (inf,inf)
            exact(request,flags,preferred,valid)
        quiet=0;retry_gaps=[]
        if case!=2:
            final=summaries[case,3]
            quiet=microseconds(final['row'])-microseconds(case_conflicts[-1]['row'])
            require(quiet>=4000000 and final['guest_ns']-selected[-1]['guest_ns']>=4000000000,
                    'full four-second original packet and guest-clock observation after final conflict')
        if case<=4:
            initial_link=values(case,0)[0];automatic=values(case,1)[0];replaced=values(case,2)[0]
            exact(initial_link,0x80 if case==2 else 0x880,inf,inf)
            require((initial_link['target']==link)==(case==2),'actual initial link-local generation algorithm')
            require(len(advertisements[case])==1,'one complete original advertisement per global case')
            ra=advertisements[case][0]
            require(summaries[case,0]['row']['index']<ra['index']<automatic['row']['index'] and
                    len([probe for probe in case_probes if probe['target']==initial_link['target'] and probe['row']['index']<ra['index']])==1,
                    'completed actual link-local DAD precedes original PIO and global observation')
            require(automatic['target']==replaced['target'] and
                    (automatic['target']==prefixes[case][:8]+identifier)==(case==2),
                    'takeover preserves actual original identity and selected generation algorithm')
            if case==2:
                require(automatic['flags']==0x100 and 58<=automatic['preferred']<=60 and automatic['valid']==automatic['preferred']+40,
                        'original completed finite EUI64 address ages normally')
                exact(replaced,0x82,inf,inf)
            else:
                exact(automatic,0x940,30,60)
                exact(replaced,{1:0x8c0,3:0x8c2,4:0x840}[case],6 if case==4 else inf,10 if case==4 else inf)
                require(selected[0]['target']==automatic['target'],'the actual replaced owner receives the conflict')
                first=one(case,9);ready=one(case,10)
                require(first['target']==ready['target'] and first['target']!=automatic['target'] and
                        first['target']!=prefixes[case][:8]+identifier,'stable retry has a fresh non-EUI64 identity')
                exact(first,{1:0x8c0,3:0x8c2,4:0x840}[case],6 if case==4 else inf,10 if case==4 else inf)
                require(ready['flags']=={1:0x880,3:0x882,4:0x800}[case], 'actual retry becomes ready with preserved raw flags')
                retry=[probe for probe in case_probes if probe['target']==first['target']]
                if case==3:
                    require(not retry,'NODAD retry sends no second global probe')
                    gap=microseconds(ready['row'])-microseconds(case_conflicts[0]['row'])
                    require(1000000<=gap<=2100000,'original stable hold before NODAD deferred completion')
                else:
                    require(len(retry)==1,'one actual stable retry DAD probe')
                    gap=microseconds(retry[0]['row'])-microseconds(case_conflicts[0]['row'])
                    require(1000000<=gap<=2100000 and first['row']['index']<retry[0]['row']['index']<ready['row']['index'],
                            'original one-to-two-second retry hold and actual tentative/ready ordering')
                retry_gaps.append(gap)
                complete=values(case,3);remaining=values(case,4)
                failed=[value for value in complete if value['target']==automatic['target']]
                active_owners=[value for value in complete if value['target']==first['target']]
                require(len(active_owners)==1 and len(failed)==int(case!=4) and len(complete)==(1 if case==4 else 2) and
                        len(remaining)==1 and remaining[0]['target']==first['target'], 'actual old and retry owners survive or disappear independently')
                if failed:exact(failed[0],0x8ca if case==3 else 0x8c8,inf,inf)
                for value in [ready,active_owners[0],remaining[0]]:
                    if case==4:
                        elapsed=value['guest_ns']-first['guest_ns']
                        require(value['flags']==0x800 and 0<value['preferred']<=6 and value['valid']==value['preferred']+4 and
                                max(0,6-(elapsed+999999999)//1000000000-1)<=value['preferred']<=min(6,6-elapsed//1000000000+1),
                                'finite retry preserves raw six/ten cache and ages against actual observations')
                    else:exact(value,0x882 if case==3 else 0x880,inf,inf)
            require(not values(case,5),'last explicit removal leaves no global address')
            for stage in ([1,2,5] if case==2 else [1,2,3,4,5]):
                require(summaries[case,stage]['preferred']==(int(retain and case==4) if stage==5 else 1),
                        'actual prefix route follows current preselected finite cleanup policy')
            deleted=[value for value in requests if value['case']==case and value['kind']==6]
            require(len(deleted)==(1 if case==2 else 2),'all required explicit owner deletions observed')
            for ordinal,value in enumerate(deleted):
                require(value['flags']==(0xffffff9d if case==4 and ordinal==0 else 0) and value['preferred']==value['valid']==0 and
                        value['target']==(automatic['target'] if ordinal==0 else one(case,9)['target']),
                        'actual explicit deletion identity and kernel result')
        else:
            require(not advertisements[case],'link-local/configured cases receive no synthesized router input')
            complete=values(case,3)
            if case<=7:
                require(len(complete)=={5:2,6:3,7:4}[case],'all permanent link-local objects remain owned')
                targets=[request['target'] for request in selected]
                require(len(set(targets))==len(targets) and all(target!=link for target in targets),
                        'all conflicted stable link-local identities are distinct and never EUI64')
                for target in targets:
                    found=[value for value in complete if value['target']==target]
                    require(len(found)==1,'each original failed permanent identity is retained exactly once')
                    exact(found[0],0x8c8,inf,inf)
                if case==7:
                    require({probe['target'] for probe in case_probes}==set(targets),'no fifth exhausted stable candidate')
                    for previous,current in zip(case_conflicts,case_probes[1:]):
                        gap=microseconds(current['row'])-microseconds(previous['row'])
                        require(1000000<=gap<=2100000,'original stable retry hold for all exhaustion attempts')
                        retry_gaps.append(gap)
                else:
                    first=one(case,9);ready=one(case,10)
                    exact(first,0x8c0,inf,inf);exact(ready,0x880,inf,inf)
                    require(first['target']==ready['target'] and first['target'] not in (*targets,link),
                            'mode-independent stable retry remains a fresh actual owner')
                    fresh=[probe for probe in case_probes if probe['target']==first['target']]
                    require(len(fresh)==1,'one actual link-local retry probe')
                    gap=microseconds(fresh[0]['row'])-microseconds(case_conflicts[0]['row'])
                    require(1000000<=gap<=2100000 and first['row']['index']<fresh[0]['row']['index']<ready['row']['index'],
                            'actual link-local retry preserves original stable hold')
                    retry_gaps.append(gap)
                    require(any(value['target']==ready['target'] and value['flags']==0x880 for value in complete),
                            'ready stable retry remains in final inventory')
                    if case==6:
                        mode=one(case,5)
                        require(mode['row']['index']<selected[0]['row']['index'] and
                                len([probe for probe in case_probes if probe['target']==link and probe['row']['index']>mode['row']['index']])==1 and
                                any(value['target']==link and value['flags']==0x80 for value in complete),
                                'mode-zero write independently adds EUI64 while old stable DAD still fails and retries')
                    require(all(value['preferred']==value['valid']==inf for value in complete),'all permanent link-local lifetimes remain infinite')
            else:
                require(not complete and summaries[case,3]['preferred']==int(retain) and
                        summaries[case,3]['guest_ns']-selected[0]['guest_ns']<8000000000,
                        'finite nonpermanent failed owner disappears before its original eight-second expiry')
                recreated=values(case,4)[0];later=values(case,5)[0];target=prefixes[case][:-1]+b'\x23'
                require(selected[0]['target']==recreated['target']==later['target']==target,'same actual configured address is recreated')
                exact(recreated,2 if case==9 else 0x40,2,8)
                require(later['flags']==(2 if case==9 else 0x20 if later['preferred']==0 else 0) and
                        (0<later['preferred']<=1 if case==9 else 0<=later['preferred']<=1) and later['valid']==later['preferred']+6 and
                        summaries[case,4]['preferred']==summaries[case,5]['preferred']==1,
                        'recreated finite owner becomes ready and keeps requested raw lifetimes')
                require(later['guest_ns']-recreated['guest_ns']>=1000000000 and
                        microseconds(later['row'])-microseconds(recreated['row'])>=1000000,
                        'full original DAD interval follows recreated metadata')
                if case==8:
                    second=case_probes[1]
                    require(second['target']==target and summaries[case,3]['row']['index']<second['row']['index']<later['row']['index'] and
                            microseconds(later['row'])-microseconds(second['row'])>=900000 and
                            later['guest_ns']-recreated['guest_ns']<8000000000,
                            'ordinary recreation sends one fresh probe after verified failed-owner removal')
                else:require(len(case_probes)==1,'NODAD recreation sends no extra probe through the whole observation')
        reports.append(dict(case=case,actual_DAD_probes=len(case_probes),actual_conflicts=len(case_conflicts),
                            quiet_us=quiet,retry_gaps_us=retry_gaps))
    return dict(passed=True,lane=lane,group=group,cases=reports,original_capture_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        actual_frames=len(rows),queried_controls=len(requests),native_clock=clock,native_multicast_reports=mld,
        firmware_sha256=firmware,native_kernel_release=native_kernel_release,retained_finite_prefix_policy=retain,
        original_packet_times_not_rescaled=True,full_F12_complete=False)
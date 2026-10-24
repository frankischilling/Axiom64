# SPDX-License-Identifier: GPL-3.0-or-later
"""Serialize changed ownership evidence and require independent reader rejection."""
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile

from ipv6_owner_capture import inspect
from ipv6_router_capture import checksum, qemu_records

COMMON = ('missing-ack','duplicate-query','wrong-adapter','wrong-nonce-option','bad-checksum','wrong-hop-limit',
          'conflict-after-ack','missing-probe','extra-probe','short-quiet-window','early-retry','late-retry',
          'backward-guest-clock','opposite-prefix-policy','truncated-capture','missing-serial-query','missing-completion')
GLOBAL = ('wrong-first-flags','wrong-cloned-cache','wrong-failed-flags','wrong-deleted-identity','orphan-permanent-prefix','wrong-pio-cache')
LIFECYCLE = ('ordinary-recreation-nodad','ordinary-recreation-cache-before-flag','invented-deprecation-wait',
             'nodad-recreation-tentative','missing-permanent-owner','wrong-exhausted-count','invented-nodad-probe')
SECRET = ('missing-secret-readback','duplicate-secret-readback','wrong-secret-value',
          'early-secret-readback','late-secret-readback','wrong-secret-scope',
          'wrong-secret-failed-flags','wrong-secret-exhausted-count','wrong-secret-retry-lifetime')


def controls(path,lane,text,group,archive=None):
    path=Path(path);original=path.read_bytes();rows=list(qemu_records(path))
    guest=bytes.fromhex(f'5254001234{16+lane:02x}')
    outcomes=[];payloads={}
    def select(kind,case=None,stage=None,predicate=lambda frame:True):
        found=[i for i,row in enumerate(rows) if row['frame'][12:14]==b'\x88\xc3' and
               row['frame'][6:12]==guest and row['frame'][20]==kind and
               (case is None or row['frame'][21]==case) and (stage is None or row['frame'][22]==stage) and predicate(row['frame'])]
        if not found:raise ValueError('negative control prerequisite missing')
        return found[0]
    def packet(kind,case=None):
        # Bound the packet selection by original BEGIN/END controls, not peer counters.
        start=select(1,case) if case is not None else 0
        stop=select(7,case) if case is not None else len(rows)
        return next(i for i in range(start,stop) if rows[i]['frame'][12:14]==b'\x86\xdd' and
                    rows[i]['frame'][20]==58 and rows[i]['frame'][54]==kind)
    def encode(items):
        order='<' if original[:4]==b'\xd4\xc3\xb2\xa1' else '>'
        data=bytearray(original[:24])
        for row in items:
            seconds,micros=divmod(row['stamp'],1000000);frame=row['frame']
            data.extend(struct.pack(order+'IIII',seconds,micros,len(frame),len(frame)));data.extend(frame)
        return bytes(data)
    def sync(log,frame):
        pattern=r'^IPV6_OWNER_CONTROL lane='+str(lane)+r' phase='+str(frame[19])+r' .*\r?$'
        flags,preferred,valid=struct.unpack_from('!III',frame,24)
        replacement=(f'IPV6_OWNER_CONTROL lane={lane} phase={frame[19]} kind={frame[20]} case={frame[21]} '
            f'stage={frame[22]} flags={flags:x} preferred={preferred} valid={valid} target={frame[36:52].hex()} '
            f'observed_ns={int.from_bytes(frame[52:60],"big")}')
        updated,count=re.subn(pattern,replacement,log,flags=re.M)
        if count!=1:raise ValueError('one actual serial query for coherent corruption')
        return updated
    def recalculate(frame):
        frame[56:58]=bytes(2)
        struct.pack_into('!H',frame,56,checksum(bytes(frame[22:54])+struct.pack('!I3xB',len(frame)-54,58)+bytes(frame[54:])))
    first_case=1 if group in ('global','secret') else 5
    na=packet(136,first_case);ns=packet(135,first_case)
    conflict=select(4,first_case);phase=rows[conflict]['frame'][19]
    ack=next(i for i,row in enumerate(rows) if row['frame'][12:14]==b'\x88\xc3' and row['frame'][:6]==guest and row['frame'][19:21]==bytes([phase,1]))
    retry_target=rows[select(9,first_case)]['frame'][36:52]
    retry=next(i for i,row in enumerate(rows) if row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]==58 and row['frame'][54]==135 and row['frame'][62:78]==retry_target)
    labels=COMMON+({'global':GLOBAL,'lifecycle':LIFECYCLE,'secret':SECRET}[group])
    with tempfile.TemporaryDirectory(prefix='axiom64-owner-damaged-') as temporary:
        temporary=Path(temporary)
        for label in labels:
            changed=copy.deepcopy(rows);log=text;raw=None
            def edit(index,action,coherent=False):
                nonlocal log
                frame=bytearray(changed[index]['frame']);action(frame);changed[index]['frame']=bytes(frame)
                if coherent:log=sync(log,frame)
            if label=='missing-ack':del changed[ack]
            elif label=='duplicate-query':changed.insert(conflict,copy.deepcopy(changed[conflict]))
            elif label=='wrong-adapter':edit(ns,lambda f:f.__setitem__(6,f[6]^1))
            elif label=='wrong-nonce-option':
                def change(f):f[78]=1;recalculate(f)
                edit(ns,change)
            elif label=='bad-checksum':edit(na,lambda f:f.__setitem__(56,f[56]^1))
            elif label=='wrong-hop-limit':edit(na,lambda f:f.__setitem__(21,254))
            elif label=='conflict-after-ack':changed[na],changed[ack]=changed[ack],changed[na]
            elif label=='missing-probe':del changed[ns]
            elif label=='extra-probe':
                index=select(7,first_case);extra=copy.deepcopy(rows[ns]);extra['stamp']=rows[index]['stamp']-1;changed.insert(index,extra)
            elif label=='short-quiet-window':
                case=1 if group=='global' else 7;index=select(3,case,3);last_na=packet(136,case)
                if case==7:
                    last_na=max(i for i,row in enumerate(rows[:index]) if row['frame'][12:14]==b'\x86\xdd' and row['frame'][20]==58 and row['frame'][54]==136)
                changed[index]['stamp']=rows[last_na]['stamp']+3000000
            elif label=='early-retry':changed[retry]['stamp']=rows[na]['stamp']+500000
            elif label=='late-retry':changed[retry]['stamp']=rows[na]['stamp']+2200000
            elif label=='backward-guest-clock':
                index=select(9,first_case);previous=max(int.from_bytes(row['frame'][52:60],'big') for row in rows[:index] if row['frame'][12:14]==b'\x88\xc3' and row['frame'][6:12]==guest)
                edit(index,lambda f:f.__setitem__(slice(52,60),(previous-1).to_bytes(8,'big')),True)
            elif label=='opposite-prefix-policy':edit(select(0),lambda f:f.__setitem__(23,1))
            elif label=='truncated-capture':raw=original[:-1]
            elif label=='missing-serial-query':
                log,count=re.subn(r'^IPV6_OWNER_CONTROL lane='+str(lane)+r' phase=0 .*\r?\n','',log,flags=re.M);assert count==1
            elif label=='missing-completion':
                log,count=re.subn(r'^IPV6_OWNER_PASS .*\r?\n?','',log,flags=re.M);assert count==1
            elif label=='wrong-first-flags':edit(select(9,1),lambda f:struct.pack_into('!I',f,24,0x940),True)
            elif label=='wrong-cloned-cache':edit(select(9,4),lambda f:struct.pack_into('!II',f,28,5,9),True)
            elif label=='wrong-failed-flags':edit(select(2,1,3,lambda f:bool(f[27]&8)),lambda f:struct.pack_into('!I',f,24,0x8c0),True)
            elif label=='wrong-deleted-identity':edit(select(6,1,0),lambda f:f.__setitem__(51,f[51]^1),True)
            elif label=='orphan-permanent-prefix':edit(select(3,1,5),lambda f:struct.pack_into('!I',f,28,1),True)
            elif label=='wrong-pio-cache':
                def change(f):struct.pack_into('!I',f,82,61);recalculate(f)
                edit(packet(134,1),change)
            elif label=='ordinary-recreation-nodad':edit(select(2,8,4),lambda f:struct.pack_into('!I',f,24,2),True)
            elif label=='ordinary-recreation-cache-before-flag':edit(select(2,8,5),lambda f:struct.pack_into('!III',f,24,0,0,6),True)
            elif label=='invented-deprecation-wait':
                stamp=int.from_bytes(rows[select(2,8,5)]['frame'][52:60],'big')+1
                log+=f'\nIPV6_OWNER_DEPRECATION_WAIT lane={lane} case=8 flags=0 preferred=0 valid=6 observed_ns={stamp}\n'
            elif label=='nodad-recreation-tentative':edit(select(2,9,4),lambda f:struct.pack_into('!I',f,24,0x40),True)
            elif label=='missing-permanent-owner':edit(select(2,5,3,lambda f:bool(f[27]&8)),lambda f:f.__setitem__(51,f[51]^1),True)
            elif label=='wrong-exhausted-count':edit(select(3,7,3),lambda f:struct.pack_into('!I',f,24,3),True)
            elif label=='invented-nodad-probe':
                index=select(2,9,5);extra=copy.deepcopy(rows[packet(135,8)]);frame=bytearray(extra['frame'])
                target=rows[select(2,9,4)]['frame'][36:52];destination=b'\xff\x02'+bytes(9)+b'\x01\xff'+target[-3:]
                frame[62:78]=target;frame[38:54]=destination;frame[:6]=b'\x33\x33\xff'+target[-3:];recalculate(frame)
                extra.update(frame=bytes(frame),stamp=rows[index]['stamp']-1);changed.insert(index,extra)
            elif label in SECRET[:6]:
                pattern=r'^IPV6_OWNER_SECRET lane='+str(lane)+r' case=7 .*\r?$'
                found=re.findall(pattern,log,re.M);assert len(found)==1
                original_line=found[0]
                if label=='missing-secret-readback':replacement=''
                elif label=='duplicate-secret-readback':replacement=original_line+'\n'+original_line
                elif label=='wrong-secret-value':replacement=original_line.replace('9abc','9abd')
                elif label=='wrong-secret-scope':replacement=original_line.replace('lane='+str(lane),'lane='+str(1-lane))
                else:
                    previous=rows[select(4,7,0)]['frame']
                    following=rows[select(4,7,1)]['frame']
                    stamp=int.from_bytes((previous if label=='early-secret-readback' else following)[52:60],'big')
                    stamp += -1 if label=='early-secret-readback' else 1
                    replacement=re.sub(r'observed_ns=\d+',f'observed_ns={stamp}',original_line)
                log,count=re.subn(pattern,lambda match:replacement,log,flags=re.M);assert count==1
            elif label=='wrong-secret-failed-flags':edit(select(2,7,3),lambda f:struct.pack_into('!I',f,24,0x8c0),True)
            elif label=='wrong-secret-exhausted-count':edit(select(3,7,3),lambda f:struct.pack_into('!I',f,24,3),True)
            elif label=='wrong-secret-retry-lifetime':edit(select(9,1),lambda f:struct.pack_into('!II',f,28,6,10),True)
            else:raise ValueError('unknown ownership corruption')
            data=raw if raw is not None else encode(changed)
            assert data!=original or log!=text
            damaged=temporary/(label+'.pcap');damaged.write_bytes(data)
            serial=temporary/(label+'.log');serial.write_text(log)
            try:inspect(damaged,lane,serial.read_text(),group)
            except ValueError as failure:rejection=str(failure)
            else:raise ValueError('changed ownership evidence was accepted: '+label)
            outcomes.append(dict(control=label,rejection=rejection,pcap_sha256=hashlib.sha256(data).hexdigest(),log_sha256=hashlib.sha256(log.encode()).hexdigest()))
            payloads[label+'.pcap']=data;payloads[label+'.log']=log.encode()
        assert path.read_bytes()==original
        if archive is not None:
            archive=Path(archive);archive.parent.mkdir(parents=True,exist_ok=True)
            payloads['manifest.json']=(json.dumps(dict(group=group,lane=lane,original_sha256=hashlib.sha256(original).hexdigest(),controls=outcomes),indent=2)+'\n').encode()
            with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED) as output:
                for name,data in payloads.items():output.writestr(name,data)
            with zipfile.ZipFile(archive) as output:
                assert output.testzip() is None and set(output.namelist())==set(payloads)
                for row in outcomes:
                    damaged=temporary/(row['control']+'-reopened.pcap');damaged.write_bytes(output.read(row['control']+'.pcap'))
                    try:inspect(damaged,lane,output.read(row['control']+'.log').decode(),group)
                    except ValueError:pass
                    else:raise ValueError('archived ownership corruption was accepted')
    return outcomes

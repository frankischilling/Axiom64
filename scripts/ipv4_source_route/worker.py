# SPDX-License-Identifier: GPL-3.0-or-later
"""Own one actual two-adapter source-route packet campaign and its evidence."""
import argparse
import errno
from pathlib import Path
import json
import os
import re
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import time

from fetch import ROOT as root
from build_musl import loader
from compile_uapi_client import audit_compile
from account_store_guest import fixture
from ipv4_source_route.runtime import capture
from ipv4_source_route.corpus import cases as packet_cases
from ipv4_source_route.applications import definitions as application_cases, transport
from ipv4_source_route.queues import definitions as queue_cases
from ipv4_source_route.controls import require
from ipv4_source_route import native as native_observer
from ipv4_source_route.corpus import option_fields
from ipv4_source_route.packets import normalized, raw_packets, client_trace, clocks, CLOCK_BOUND_NS
from tcp6.inputs import digest, freeze
from tcp_fixture_inputs import audit_fixture
def run(mode, profile, phase, stage, image=None, firmware='bios', transport_kind='modern', source_directory=None):
    require(mode in ('native','guest') and profile in ('native','static','dynamic') and
            phase in ('packets','applications','queues') and (mode=='native' or profile!='native') and
            firmware in ('bios','uefi') and transport_kind in ('modern','legacy'), 'fixed worker configuration')
    stage=Path(stage)
    require(stage.resolve().is_relative_to((root/'build').resolve()), 'designated ignored worker output')
    stage.mkdir(parents=True,exist_ok=False)
    shutil.copy2(Path(__file__),stage/'controller.py')
    (stage/'source').mkdir()
    if source_directory is None:
        source=freeze(stage/'source')
    else:
        source_directory=Path(source_directory)
        source=json.loads((source_directory/'binding.json').read_text())
        for name in ('source.zip','source-inputs.json'):
            os.link(source_directory/name,stage/'source'/name)
    program=root/'build'/('ipv4-source-wire-'+profile)
    shutil.copy2(program,stage/'program')
    shutil.copy2(program.with_suffix('.inputs.json'),stage/'program.inputs.json')
    cases={'packets':packet_cases,'applications':application_cases,'queues':queue_cases}[phase]()
    selector=selectors.DefaultSelector()
    channels={}
    ingress_channels={}
    ingress_wire=[]
    ingress_link_events=[]
    native_states=[]
    raw_receipts=[]
    auxiliary=[]
    boot_auxiliary=[]
    buffers={}
    listeners=[]
    def run(*arguments):
        subprocess.run(arguments,check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL)
    read_fd=write_fd=None
    environment=dict(os.environ)
    if mode=='native':
        parent=int(os.environ['IPV4_SOURCE_PARENT_NETNS'])
        assert Path('/proc/self/ns/net').stat().st_ino!=parent
        run('ip','link','set','lo','up')
        offloads={}
        for index in range(2):
            run('ip','link','add','eth'+str(index),'type','veth','peer','name','peer'+str(index))
            run('ip','link','set','eth'+str(index),'address','02:00:00:00:00:0'+str(index+1))
            run('ip','link','set','peer'+str(index),'address','02:00:00:00:01:0'+str(index+1))
            run('ip','link','set','peer'+str(index),'up')
            for interface in ('eth'+str(index),'peer'+str(index)):
                before=subprocess.check_output(['ethtool','-k',interface],text=True)
                run('ethtool','-K',interface,'tx','off','tso','off','gso','off','gro','off')
                after=subprocess.check_output(['ethtool','-k',interface],text=True)
                assert all(field+': off' in after for field in ('tx-checksumming','tcp-segmentation-offload','generic-segmentation-offload','generic-receive-offload'))
                offloads[interface]=dict(before=before,after=after)
            channel=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
            channel.setsockopt(263,8,1)
            channel.bind(('peer'+str(index),0));channel.setblocking(False)
            channels[index]=channel
            selector.register(channel,selectors.EVENT_READ,('network',index))
            monitor=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
            monitor.setsockopt(263,8,1)
            monitor.bind(('eth'+str(index),0));monitor.setblocking(False)
            ingress_channels[index]=monitor
            selector.register(monitor,selectors.EVENT_READ,('ingress',index))
        (stage/'offloads.json').write_text(json.dumps(offloads,indent=2))
        native_policy=native_observer.begin(stage)
        read_fd,write_fd=os.pipe()
        environment.update(IPV4_SOURCE_RUNTIME_FD=str(read_fd))
        executable=loader('build') if profile=='dynamic' else program
        command=[str(executable),str(program),str(len(cases))] if profile=='dynamic' else [str(program),str(len(cases))]
    else:
        assert mode=='guest' and profile in ('static','dynamic')
        def builder(provider,linkage,directory):
            assert provider=='build' and linkage==profile
            return program,audit_compile(program,root)
        if image is None:
            image=fixture(stage,'build',profile,program_builder=builder,filename='ipv4-source-wire',
                          command='/bin/ipv4-source-wire '+str(len(cases)))
        else:
            for name in ('image.iso','kernel.elf','root.cpio','products.json','compiler-inputs.json'):
                os.link(Path(image)/name,stage/name)
            image=stage/'image.iso'
        products=json.loads((stage/'products.json').read_text())
        executables={name:row['sha256'] for name,row in products.items() if name not in ('kernel.elf','root.cpio','image.iso')}
        script=f'#!/bin/sh\nset -e\n/bin/ipv4-source-wire {len(cases)}\necho AXIOM64_TESTS_PASS\n'.encode()
        audit_fixture(image,products['kernel.elf']['sha256'],executables,script,products['root.cpio']['sha256'])
        command=['qemu-system-x86_64','-machine','pc','-cpu','max','-m','256M','-cdrom',str(image),
                 '-display','none','-serial','stdio','-monitor','none','-no-reboot',
                 '-device','isa-debug-exit,iobase=0xf4,iosize=0x04']
        if firmware=='uefi':
            for firmware_source,target in (('/usr/share/OVMF/OVMF_CODE_4M.fd','OVMF_CODE.fd'),
                                  ('/usr/share/OVMF/OVMF_VARS_4M.fd','OVMF_VARS.original.fd')):
                shutil.copy2(firmware_source,stage/target)
            shutil.copy2(stage/'OVMF_VARS.original.fd',stage/'OVMF_VARS.fd')
            command+=['-drive','if=pflash,format=raw,readonly=on,file='+str(stage/'OVMF_CODE.fd'),
                      '-drive','if=pflash,format=raw,file='+str(stage/'OVMF_VARS.fd')]
        device='virtio-net-pci,'+('disable-legacy=on' if transport_kind=='modern' else 'disable-modern=on')
        for index,device in enumerate((device,'e1000')):
            server=socket.socket();server.bind(('127.0.0.1',0));server.listen(1);server.settimeout(15)
            listeners.append(server)
            command+=['-netdev',f'socket,id=net{index},connect=127.0.0.1:{server.getsockname()[1]}',
                      '-device',device+f',netdev=net{index},mac=02:00:00:00:00:0{index+1}']
    (stage/'command.json').write_text(json.dumps(command,indent=2))
    began=time.monotonic_ns()
    process=subprocess.Popen(command,cwd=root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
        pass_fds=() if read_fd is None else (read_fd,),env=environment)
    (stage/'process.json').write_text(json.dumps(dict(pid=process.pid,status='running')))
    serial=bytearray()
    serial_scanned=0
    wire=[]
    boot_wire=[]
    current=-1
    holding=False
    pending_arp=None
    timestamp_receipts=[]
    retry_receipts=[]
    tcp_state=None
    commands=[]
    def record_frame(index,frame,direction,packet_type=None):
        selected=boot_wire if current<0 else wire
        selected.append(dict(case=current,index=index,direction=direction,frame=frame.hex(),
                         monotonic_ns=time.monotonic_ns(),realtime_ns=time.time_ns(),packet_type=packet_type))
    def send(index,frame):
        if mode=='native':
            assert channels[index].send(frame)==len(frame)
        else:
            channels[index].sendall(len(frame).to_bytes(4,'big')+frame)
        record_frame(index,frame,'input')
    def arp_reply(index,frame):
        peer=bytes((2,0,0,0,1,index+1))
        return frame[6:12]+peer+b'\x08\x06'+struct.pack('!HHBBH',1,0x800,6,4,2)+peer+frame[38:42]+frame[22:28]+frame[28:32]
    def receive(index,frame,packet_type=None):
        nonlocal pending_arp
        record_frame(index,frame,'output',packet_type)
        if current<0:
            return
        if frame[6:12]!=bytes((2,0,0,0,0,index+1)):
            return
        if frame[12:14]==b'\x08\x00' and any(kind==68 for _,kind,_ in option_fields(frame[14:])):
            timestamp_receipts.append(wire[-1]['monotonic_ns'])
        if tcp_state is not None and frame[12:14]==b'\x08\x00' and frame[23]==6:
            ip=frame[14:14+int.from_bytes(frame[16:18],'big')]
            tcp=ip[(ip[0]&15)*4:]
            assert len(tcp)>=20
            sequence=int.from_bytes(tcp[4:8],'big')
            flags=tcp[13]
            data=tcp[(tcp[12]>>4)*4:]
            if flags&2:
                assert flags&16 and int.from_bytes(tcp[8:12],'big')==row['sequence']+1
                assert tcp_state['isn'] in (None,sequence)
                tcp_state['isn']=sequence
            if flags&1:tcp_state['fin']=True
            if data:tcp_state['data']+=data
            if flags&3 or data:
                acknowledgement=(sequence+len(data)+bool(flags&1)+bool(flags&2))&0xffffffff
                send(0,transport(row,flags=16,acknowledgement=acknowledgement,sequence=tcp_state['peer_sequence']))
        if frame[12:14]==b'\x08\x06' and len(frame)>=42 and frame[20:22]==b'\0\1':
            assert frame[14:22]==struct.pack('!HHBBH',1,0x800,6,4,1)
            assert frame[38:42]==bytes((10,index,0,2)),'unexpected actual next-hop ARP address'
            if row.get('suppress_arp') and index==1:
                retry_receipts.append(wire[-1]['monotonic_ns'])
                return
            if holding and index==1:
                assert pending_arp is None,'duplicate held ARP before mutation'
                pending_arp=frame
            else:
                send(index,arp_reply(index,frame))
    def pump(timeout):
        nonlocal serial_scanned
        for key,_ in selector.select(timeout):
            kind,index=key.data
            if kind=='serial':
                data=os.read(process.stdout.fileno(),16384)
                if data:
                    serial.extend(data)
                    while True:
                        end=serial.find(b'\n',serial_scanned)
                        if end<0:
                            break
                        line=bytes(serial[serial_scanned:end]).rstrip(b'\r')
                        serial_scanned=end+1
                        if line.startswith(b'IPV4_SOURCE_RAW_CLOCK '):
                            match=re.match(rb'IPV4_SOURCE_RAW_CLOCK case=(\d+) packet=(\d+) ',line)
                            require(match is not None,'complete raw-clock receipt identity')
                            raw_receipts.append(dict(case=int(match[1]),packet=int(match[2]),monotonic_ns=time.monotonic_ns()))
                    (stage/'client.log').write_bytes(serial)
                    if b'IPV4_SOURCE_WIRE_FAIL' in serial:
                        raise RuntimeError(serial.decode(errors='replace')[-1500:])
                else:
                    selector.unregister(process.stdout)
                continue
            if kind=='ingress':
                try:
                    frame,controls,flags,address=key.fileobj.recvmsg(65535,256)
                except OSError as error:
                    if error.errno!=errno.ENETDOWN:
                        raise
                    ingress_link_events.append(dict(case=current,index=index,errno=error.errno,
                        monotonic_ns=time.monotonic_ns()))
                    continue
                require(not flags,'complete independent ingress capture')
                ingress_wire.append(dict(case=current,index=index,frame=frame.hex(),packet_type=address[2],
                    monotonic_ns=time.monotonic_ns(),realtime_ns=time.time_ns()))
                continue
            if mode=='native':
                frame,controls,flags,address=key.fileobj.recvmsg(65535,256)
                assert not flags
                selected=boot_auxiliary if current<0 else auxiliary
                selected.append(dict(case=current,index=index,wire_offset=len(boot_wire if current<0 else wire),frame_sha256=__import__('hashlib').sha256(frame).hexdigest(),
                    controls=[dict(level=level,kind=kind,data=value.hex()) for level,kind,value in controls]))
                receive(index,frame,address[2])
            else:
                data=key.fileobj.recv(65535)
                if not data:
                    selector.unregister(key.fileobj);continue
                buffers[index].extend(data)
                while len(buffers[index])>=4:
                    size=int.from_bytes(buffers[index][:4],'big')
                    assert 14<=size<=65553
                    if len(buffers[index])<4+size:break
                    frame=bytes(buffers[index][4:4+size]);del buffers[index][:4+size]
                    receive(index,frame)
    def marker(value,timeout=15):
        deadline=time.monotonic()+timeout
        while value.encode() not in serial.replace(b'\r\n',b'\n'):
            if process.poll() is not None:
                pump(0)
                if value.encode() in serial.replace(b'\r\n',b'\n'):
                    return
                raise RuntimeError('process ended before marker: '+value+'\n'+serial.decode(errors='replace')[-1500:])
            assert time.monotonic()<deadline,'marker timeout '+value
            pump(.02)
    def command_line(value):
        encoded=b'!' if value==f'guard {current}' else (value+'\n').encode()
        commands.append(dict(command=value,monotonic_ns=time.monotonic_ns(),input_hex=encoded.hex()))
        process.stdin.write(encoded);process.stdin.flush()
    def complete_line(prefix):
        marker(prefix)
        deadline=time.monotonic()+5
        while True:
            text=serial.replace(b'\r\n',b'\n')
            offset=text.rfind(prefix.encode())
            end=text.find(b'\n',offset)
            if end>=0:return text[offset:end].decode()
            assert time.monotonic()<deadline,'incomplete command record'
            pump(.02)
    try:
        if mode=='native':
            os.close(read_fd);read_fd=None
            capture(process,program,executable,stage,profile,parent)
            os.write(write_fd,b'\xa5');os.close(write_fd);write_fd=None
        else:
            for index,server in enumerate(listeners):
                channel,_=server.accept();channel.setblocking(False)
                channels[index]=channel;buffers[index]=bytearray()
                selector.register(channel,selectors.EVENT_READ,('network',index))
        os.set_blocking(process.stdout.fileno(),False)
        selector.register(process.stdout,selectors.EVENT_READ,('serial',None))
        marker('IPV4_SOURCE_WIRE_KERNEL ')
        results=[]
        for current,row in enumerate(cases):
            action=row.get('action','packet')
            policy=row['policy']
            mtu=1500 if row['kind']=='held' else 576
            forwarding=policy.get('forwarding',1)
            command_line(f"case {current} {mtu} {policy.get('all_source',1)} {policy.get('link_source',1)} {forwarding} {policy.get('link_forwarding',forwarding)}")
            marker(f'IPV4_SOURCE_WIRE_READY case={current}\n')
            if row.get('prepare_alias'):
                command_line(f'alias {current}')
                marker(f'IPV4_SOURCE_ALIAS case={current} phase=prepared address=0a020001\n')
            if mode=='native':
                native_states.append(native_observer.state(current,'ready'))
                (stage/'native-state.json').write_text(json.dumps(native_states,indent=2))
            source_request_ns=source_response_ns=None
            if phase=='queues':
                source_request_ns=time.monotonic_ns()
                command_line(f'sync {current}')
                complete_line(f'IPV4_SOURCE_SYNC case={current} phase=input ')
                source_response_ns=time.monotonic_ns()
                require(source_response_ns-source_request_ns<=CLOCK_BOUND_NS,'unchanged one-second source synchronization bound')
            tcp_state=None
            if action in ('udp-return','tcp-accept'):
                kind='tcp' if row['protocol']==6 else 'udp-bound' if row.get('bound') else 'udp'
                command_line(f"app-open {current} {kind} {row['port']}")
                complete_line(f'IPV4_SOURCE_APP_OPEN case={current} ')
                if kind=='tcp':tcp_state=dict(isn=None,peer_sequence=row['sequence']+1,data=b'',fin=False)
            start=len(wire)
            input_began=time.monotonic_ns()
            input_realtime=time.time_ns()
            holding=row['kind']=='held'
            pending_arp=None
            timestamp_receipts.clear()
            retry_receipts.clear()
            sample_requests=[]
            error_guard=None
            clock_request_ns=clock_response_ns=None
            for frame in row['transmitted']:
                send(0,bytes.fromhex(frame))
            if action=='tcp-accept':
                limit=time.monotonic()+2
                while tcp_state['isn'] is None and time.monotonic()<limit:pump(.02)
                assert tcp_state['isn'] is not None,'actual source-routed SYN-ACK'
                command_line(f'app-accept {current}')
                complete_line(f'IPV4_SOURCE_APP_OPTIONS case={current} owner=accepted phase=after ')
                tcp_state['peer_sequence']=row['sequence']+1+len(bytes.fromhex(row['payload']))+1
                send(0,transport(row,flags=25,acknowledgement=(tcp_state['isn']+1)&0xffffffff,
                                 sequence=row['sequence']+1,data=bytes.fromhex(row['payload'])))
            if action in ('udp-return','tcp-accept'):
                command_line(f'app-receive {current}')
                marker(f'IPV4_SOURCE_APP_RECEIVED case={current}\n')
                if tcp_state is not None:
                    limit=time.monotonic()+2
                    while (not tcp_state['fin'] or tcp_state['data']!=bytes.fromhex(row['payload'])) and time.monotonic()<limit:pump(.02)
                    assert tcp_state['fin'] and tcp_state['data']==bytes.fromhex(row['payload']),'actual TCP echo and FIN'
                command_line(f'app-close {current}')
                marker(f'IPV4_SOURCE_APP_CLOSED case={current}\n')
            if holding:
                deadline=time.monotonic()+8
                while pending_arp is None and time.monotonic()<deadline:
                    pump(.02)
                assert pending_arp is not None,'actual held next-hop ARP request'
                assert pending_arp[:42]==bytes.fromhex(row['arp_request'])[:42]
                command_line(f"mutate {current} {row['mutation']}")
                marker(f"IPV4_SOURCE_WIRE_MUTATED case={current} action={row['mutation']}\n")
                if row.get('prepare_alias'):
                    marker(f'IPV4_SOURCE_ALIAS case={current} phase=survived address=0a020001\n')
                holding=False
                send(1,arp_reply(1,pending_arp))
            observation_began=time.monotonic_ns()
            seconds=row.get('observation_seconds',5 if row['kind']=='held' else 1)
            deadline=time.monotonic()+seconds
            def sample(phase):
                requested=time.monotonic_ns()
                command_line(f'sample {current} {phase}')
                complete_line(f'IPV4_SOURCE_SAMPLE case={current} phase={phase} ')
                responded=time.monotonic_ns()
                assert responded-requested<=CLOCK_BOUND_NS
                sample_requests.append(dict(phase=phase,requested_ns=requested,responded_ns=responded))
            while time.monotonic()<deadline:
                timeout=min(.02,max(0,deadline-time.monotonic()))
                if error_guard is not None and error_guard["requested_ns"] is None:
                    timeout=min(timeout,max(0,(retry_receipts[2]+980000000-time.monotonic_ns())/1000000000))
                pump(timeout)
                if phase=="queues" and row["suppress_arp"] and row["complete_route"] and len(retry_receipts)==3:
                    if error_guard is None:
                        requested=time.monotonic_ns()
                        command_line(f"guard-arm {current}")
                        complete_line(f"IPV4_SOURCE_GUARD_ARM case={current}")
                        responded=time.monotonic_ns()
                        require(responded-requested<=CLOCK_BOUND_NS,"original one-second guard arm response bound")
                        error_guard=dict(arm_requested_ns=requested,arm_responded_ns=responded,
                            requested_ns=None,responded_ns=None)
                    if error_guard["requested_ns"] is None and time.monotonic_ns()>=retry_receipts[2]+980000000:
                        error_guard["requested_ns"]=time.monotonic_ns()
                        command_line(f"guard {current}")
                        complete_line(f"IPV4_SOURCE_GUARD case={current} ")
                        error_guard["responded_ns"]=time.monotonic_ns()
                        require(error_guard["responded_ns"]-error_guard["requested_ns"]<=CLOCK_BOUND_NS,
                            "original one-second empty guard response bound")
                if row.get('timed') and not sample_requests and retry_receipts:
                    assert len(retry_receipts)==1
                    sample('early')
                    assert sample_requests[-1]['responded_ns']-retry_receipts[0]<=CLOCK_BOUND_NS
                    command_line(f'drain {current}')
                    marker(f'IPV4_SOURCE_DRAINED case={current} packets={int(row["name"].endswith("complete-loose"))}\n')
                if row.get('timed') and len(sample_requests)==1 and len(retry_receipts)==3:
                    sample('late-before')
                    assert sample_requests[-1]['responded_ns']-retry_receipts[2]<=CLOCK_BOUND_NS
                if row.get('timed') and len(sample_requests)==2:
                    events=timestamp_receipts[:1]+[value['monotonic_ns'] for value in raw_receipts
                        if value['case']==current and value['packet']==1]
                    if events:
                        sample('late-after')
                        require(sample_requests[-1]['responded_ns']-min(events)<=CLOCK_BOUND_NS,
                            'unchanged one-second delayed error observer bound')
                if phase!='queues' and timestamp_receipts and clock_request_ns is None:
                    assert row['clocked'],'unexpected actual timestamp output'
                    clock_request_ns=time.monotonic_ns()
                    command_line(f'clock {current}')
                    complete_line(f'IPV4_SOURCE_WIRE_CLOCK case={current} phase=after ')
                    clock_response_ns=time.monotonic_ns()
                    assert clock_response_ns-timestamp_receipts[0]<=CLOCK_BOUND_NS,'unchanged one-second clock observer response bound'
            ended=time.monotonic_ns()
            assert ended-observation_began>=seconds*1000000000
            if row.get('timed'):
                assert len(retry_receipts)==3 and len(sample_requests)==3
            source_clocks=clocks(serial.decode(errors='replace'),current,len(cases))
            assert set(source_clocks)==({'before','after'} if row['clocked'] else {'before'}),'complete source-clock brackets'
            source_before_ms=source_clocks['before']['realtime_ns']//1000000
            source_after_ms=source_clocks.get('after',{}).get('realtime_ns',0)//1000000
            command_line(f'observe {current}')
            complete_line(f'IPV4_SOURCE_WIRE_OBSERVED case={current} ')
            if mode=='native':
                native_states.append(native_observer.state(current,'after'))
                (stage/'native-state.json').write_text(json.dumps(native_states,indent=2))
            def packet(value,reference=False):
                frame=bytes.fromhex(value['frame'])
                if value['direction']!='output' or frame[12:14]!=b'\x08\x00' or frame[6:12]!=bytes((2,0,0,0,0,value['index']+1)):
                    return None
                if phase=='queues':
                    length=int.from_bytes(frame[16:18],'big')
                    ip=frame[14:14+length];headers=frame[:14]
                    assert len(ip)==length
                else:
                    headers,ip=normalized(frame,reference=reference,source_before_ms=source_before_ms,
                        source_after_ms=source_after_ms)
                return value['index'],headers,ip
            actual=[]
            for value in wire[start:]:
                parsed=packet(value)
                if parsed is not None:actual.append(parsed)
            expected=None
            equal=None
            if phase=='packets':
                expected=[packet(dict(direction='output',index=value['index'],frame=value['frame']),True)
                          for value in row['expected']]
                equal=actual==expected
            raw=raw_packets(serial.decode(errors='replace'),current,len(cases))
            if row['raw_inputs'] is not None:
                assert raw==row['raw_inputs'],('raw input',row['name'],raw,row['raw_inputs'])
            results.append(dict(name=row['name'],case=current,packets=len(actual),matched_native_reference=equal,
                                input_began_ns=input_began,input_realtime_ns=input_realtime,
                                observation_began_ns=observation_began,observation_seconds=seconds,ended_ns=ended,
                                raw_inputs=raw,source_clocks=source_clocks,clock_request_ns=clock_request_ns,
                                clock_response_ns=clock_response_ns,timestamp_receipts=timestamp_receipts.copy(),
                                output_packets=[dict(index=index,ethernet=headers.hex(),ip=ip.hex()) for index,headers,ip in actual]))
            if phase=='packets':
                del results[-1]['output_packets']
            elif phase=='queues':
                results[-1]['sample_requests']=sample_requests
                results[-1]['error_guard']=error_guard
                results[-1]['raw_receipts']=[value for value in raw_receipts if value['case']==current]
                results[-1]['source_request_ns']=source_request_ns
                results[-1]['source_response_ns']=source_response_ns
            (stage/'results.json').write_text(json.dumps(results,indent=2))
            (stage/'wire.json').write_text(json.dumps(wire,indent=2))
            if phase=='packets':
                assert equal,('native packet comparison',row['name'])
            print(json.dumps({key:value for key,value in results[-1].items() if key!='raw_inputs'}),flush=True)
        command_line('finish')
        marker('IPV4_SOURCE_WIRE_PASS cases='+str(len(cases)))
        if mode=='guest':
            marker('AXIOM64_EXIT status=0')
        deadline=time.monotonic()+10
        while process.poll() is None and time.monotonic()<deadline:
            pump(.02)
        process.wait(timeout=1)
        assert process.returncode==(0 if mode=='native' else 1)
        raw_matrix=client_trace(serial.decode(errors='replace'),cases,mode=='native')
        assert raw_matrix==[row['raw_inputs'] for row in results]
        inputs=json.loads((stage/'source/source-inputs.json').read_text())
        assert all(digest(root/name)==value for name,value in inputs.items())
        (stage/'completed.json').write_text(json.dumps(dict(passed=True,mode=mode,profile=profile,cases=len(cases),source=source,
            controller_sha256=digest(stage/'controller.py'),program_sha256=digest(stage/'program'),
            source_stable=True,phase=phase,firmware=firmware,transport=transport_kind,full_source_route_acceptance=False),indent=2))
    finally:
        if process.poll() is None:
            process.kill();process.wait()
        for descriptor in (read_fd,write_fd):
            if descriptor is not None:os.close(descriptor)
        if mode=='native':
            native_observer.finish(stage,native_policy)
            statistics={str(index):dict(zip(('packets','drops'),struct.unpack('II',channel.getsockopt(263,6,8))))
                        for index,channel in channels.items()}
            (stage/'packet-statistics.json').write_text(json.dumps(statistics,indent=2))
            assert all(value['drops']==0 for value in statistics.values()),'zero native packet-socket drops'
            statistics={str(index):dict(zip(('packets','drops'),struct.unpack('II',channel.getsockopt(263,6,8))))
                        for index,channel in ingress_channels.items()}
            (stage/'ingress-statistics.json').write_text(json.dumps(statistics,indent=2))
            require(all(value['drops']==0 for value in statistics.values()),'zero independent ingress capture drops')
        for channel in channels.values():channel.close()
        for channel in ingress_channels.values():channel.close()
        for server in listeners:server.close()
        selector.close()
        (stage/'client.log').write_bytes(serial)
        (stage/'wire.json').write_text(json.dumps(wire,indent=2))
        (stage/'commands.json').write_text(json.dumps(commands,indent=2))
        (stage/'auxiliary.json').write_text(json.dumps(auxiliary,indent=2))
        (stage/'boot-wire.json').write_text(json.dumps(boot_wire,indent=2))
        (stage/'boot-auxiliary.json').write_text(json.dumps(boot_auxiliary,indent=2))
        (stage/'ingress-wire.json').write_text(json.dumps(ingress_wire,indent=2))
        (stage/'ingress-link-events.json').write_text(json.dumps(ingress_link_events,indent=2))
        (stage/'raw-receipts.json').write_text(json.dumps(raw_receipts,indent=2))
        (stage/'process.json').write_text(json.dumps(dict(pid=process.pid,status='completed',returncode=process.returncode,
            elapsed_ns=time.monotonic_ns()-began,log_sha256=digest(stage/'client.log')),indent=2))
        process.stdin.close()
        process.stdout.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('native','guest'))
    parser.add_argument('profile',choices=('native','static','dynamic'))
    parser.add_argument('phase',choices=('packets','applications','queues'))
    parser.add_argument('directory',type=Path)
    parser.add_argument('--image',type=Path)
    parser.add_argument('--firmware',choices=('bios','uefi'),default='bios')
    parser.add_argument('--transport',choices=('modern','legacy'),default='modern')
    parser.add_argument('--source',type=Path)
    args=parser.parse_args()
    run(args.mode,args.profile,args.phase,args.directory,args.image,args.firmware,args.transport,args.source)


if __name__=='__main__':
    main()

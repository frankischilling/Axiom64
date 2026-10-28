#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject serialized semantic, source and boot-product changes to raw UDP evidence."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from ipv4_raw_udp_evidence import MARKER, verify
from ipv4_multicast_capture import checksum


def encoded(value):return (json.dumps(value,indent=2)+'\n').encode()


def changed_log(body, select, mutate, *, remove=False, append=None):
    lines=[];selected=False
    for line in body.decode().splitlines():
        if line.startswith('{'):
            row=json.loads(line)
            if not selected and select(row):
                selected=True
                if remove:continue
                mutate(row);line=json.dumps(row,separators=(',',':'))
        lines.append(line)
    assert selected
    if append is not None:lines.append(json.dumps(append,separators=(',',':')))
    return ('\n'.join(lines)+'\n').encode()


def run(source,output):
    source,output=source.resolve(),output.resolve()
    if not source.is_relative_to(ROOT/'build') or not output.is_relative_to(ROOT/'build') or output.is_relative_to(source):
        raise ValueError('raw UDP source and fresh controls must stay separately below build/')
    positive=verify(source)
    originals={p.relative_to(source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
    base=json.loads((source/'manifest.json').read_text());variants=[]
    label='guest-static-bios';name=label+'/client.log';body=(source/name).read_bytes()
    def log_variant(title,select,mutate,reason,**kwargs):
        variants.append((title,{name:changed_log(body,select,mutate,**kwargs)},reason))
    log_variant('wrong-raw-protocol-scalar',lambda r:r.get('kind')=='scalar' and r['label']=='raw-udp-protocol',
                lambda r:r.update(value=1),'actual raw UDP scalar and address results')
    log_variant('bind-port-leaks-into-protocol-metadata',lambda r:r.get('kind')=='name' and r['label']=='raw-udp-bound-name',
                lambda r:r.update(port=55555),'actual raw UDP scalar and address results')
    log_variant('fault-error-before-protocol-rejection',lambda r:r.get('kind')=='operation' and r['label']=='raw-udp-filter-get-invalid-pointers',
                lambda r:r.update(errno=14),'complete native raw UDP operation and error order')
    def packet_byte(row,offset,value):
        packet=bytearray.fromhex(row['hex']);packet[offset]=value;packet[10:12]=b'\0\0'
        struct.pack_into('!H',packet,10,checksum(bytes(packet[:20])));row['hex']=packet.hex()
    log_variant('ICMP-instead-of-UDP-valid-checksum',lambda r:r.get('kind')=='packet' and r['label']=='unicast-raw',
                lambda r:packet_byte(r,9,1),'actual complete raw UDP IPv4 header and checksum')
    log_variant('wrong-source-valid-IP-checksum',lambda r:r.get('kind')=='packet' and r['label']=='unicast-raw',
                lambda r:packet_byte(r,15,2),'actual raw UDP IP source destination and TTL')
    def payload(row):
        packet=bytearray.fromhex(row['hex']);packet[-1]^=1;row['hex']=packet.hex()
    log_variant('changed-actual-payload-byte',lambda r:r.get('kind')=='packet' and r['label']=='unicast-raw',payload,
                'actual complete raw UDP payload bytes')
    log_variant('forged-receive-byte-count',lambda r:r.get('kind')=='packet' and r['label']=='unicast-raw',
                lambda r:r.update(returncode=r['returncode']-1),'actual raw UDP receive result and source address')
    log_variant('missing-maximum-IP-packet',lambda r:r.get('kind')=='packet' and r['label']=='maximum-raw-packet',lambda r:None,
                'complete actual raw UDP packet and source-filter inventory',remove=True)
    log_variant('short-quiet-observation',lambda r:r.get('kind')=='quiet',lambda r:r.update(end_ns=r['begin_ns']+100000000),
                'complete unscaled 200ms raw UDP quiet observation')
    def valid_udp(row):
        packet=bytearray.fromhex(row['hex']);packet[26:28]=b'\0\0'
        pseudo=bytes(packet[12:20])+b'\0\x11'+struct.pack('!H',len(packet)-20)
        struct.pack_into('!H',packet,26,checksum(pseudo+packet[20:]) or 65535);row['hex']=packet.hex()
    log_variant('invalid-UDP-replaced-by-valid-UDP',lambda r:r.get('kind')=='packet' and r['label']=='invalid-checksum-raw',valid_udp,
                'actual complete raw UDP payload bytes')
    observed=[json.loads(line) for line in body.decode().splitlines() if line.startswith('{')]
    forbidden=copy.deepcopy(next(r for r in observed if r.get('kind')=='packet' and r['label']=='initial-A-receiver0'))
    forbidden['label']='initial-A-receiver1'
    variants.append(('blocked-source-echo',{name:body+(json.dumps(forbidden)+'\n').encode()},
                     'complete actual raw UDP packet and source-filter inventory'))
    log_variant('final-description-interest-not-removed',lambda r:r.get('kind')=='phase' and r['label']=='after-final-A',
                lambda r:r.update(expected_receivers=4),'complete source membership and final-description phases')
    log_variant('missing-original79-final-operation',lambda r:r.get('operation')=='raw-filter',lambda r:None,
                'all original79 multicast ABI operations retained',remove=True)
    compiler_name=label+'/program.elf.inputs.json';compiler=json.loads((source/compiler_name).read_text())
    compiler['sources']['userspace/tests/net/ipv4_raw_udp.c']='0'*64
    variants.append(('foreign-compiler-source',{compiler_name:encoded(compiler)},'actual raw UDP compilation and original source'))
    binary_name=label+'/program.elf';binary=bytearray((source/binary_name).read_bytes());binary[24:32]=bytes(8)
    elf_compiler=json.loads((source/compiler_name).read_text())
    elf_compiler['product']=dict(bytes=len(binary),sha256=hashlib.sha256(binary).hexdigest())
    variants.append(('ELF-entry-outside-loads',{binary_name:bytes(binary),compiler_name:encoded(elf_compiler)},
                     'actual ELF entry in executable load segment'))
    archive_name=label+'/root.cpio';archive=bytearray((source/archive_name).read_bytes());program=(source/binary_name).read_bytes()
    position=archive.find(program);assert position>=0 and archive.find(program,position+1)==-1;archive[position+1000]^=1
    variants.append(('different-initramfs-program',{archive_name:bytes(archive)},'actual raw UDP client inside guest initramfs'))
    image_name=label+'/image.iso';image=bytearray((source/image_name).read_bytes());kernel=(source/label/'kernel.elf').read_bytes()
    position=image.find(kernel);assert position>=0 and image.find(kernel,position+1)==-1;image[position]^=1
    variants.append(('different-actual-ISO-kernel',{image_name:bytes(image)},'actual raw UDP ISO contains retained kernel and initramfs'))
    changed=copy.deepcopy(base);next(c for c in changed['cases'] if c['label']==label)['kernel_sha256']='0'*64
    variants.append(('foreign-guest-kernel-fingerprint',{'manifest.json':encoded(changed)},'actual raw UDP guest kernel fingerprint'))
    native='linux617-native/native-kernel';kernel=bytearray((source/native).read_bytes());kernel[0]^=1
    variants.append(('different-pinned-native-kernel',{native:bytes(kernel)},'actual pinned native raw UDP kernel image'))
    control='old-guest-static-bios/client.log'
    variants.append(('old-guest-forged-success',{control:(source/control).read_bytes()+MARKER.encode()+b'\n'},
                     'original unsupported raw UDP guest remains rejected'))
    control='old-linux617-native/client.log'
    variants.append(('down-loopback-forged-success',{control:(source/control).read_bytes()+MARKER.encode()+b'\n'},
                     'original down-loopback native fixture remains rejected'))
    changed=copy.deepcopy(base);changed['cases']=[c for c in changed['cases'] if c['label']!='guest-dynamic-uefi']
    variants.append(('missing-required-guest-profile',{'manifest.json':encoded(changed)},'complete raw UDP comparison inventory'))
    native='linux7-static/client.log';native_body=(source/native).read_bytes()
    variants.append(('foreign-actual-native-release',{native:changed_log(native_body,lambda r:r.get('kind')=='kernel',lambda r:r.update(release='0.0.0-unmeasured'))},
                     'actual raw UDP execution domain and kernel'))
    name='linux66-native/program.elf';binary=bytearray((source/name).read_bytes());binary[9]^=1
    compiler_name='linux66-native/program.elf.inputs.json';compiler=json.loads((source/compiler_name).read_text())
    compiler['product']=dict(bytes=len(binary),sha256=hashlib.sha256(binary).hexdigest())
    variants.append(('different-executable-for-same-linkage',{name:bytes(binary),compiler_name:encoded(compiler)},
                     'same actual raw UDP executable for each linkage'))
    label='guest-dynamic-uefi';archive_name=label+'/root.cpio';image_name=label+'/image.iso'
    original=(source/archive_name).read_bytes();archive=bytearray(original)
    from ipv4_multicast_capture import cpio
    library=cpio(original)['lib/ld-musl-x86_64.so.1'][1];at=archive.find(library)
    assert at>=0 and archive.find(library,at+1)==-1;archive[at+9]^=1
    image=bytearray((source/image_name).read_bytes());position=image.find(original)
    assert position>=0 and image.find(original,position+1)==-1;image[position+at+9]^=1
    variants.append(('different-runtime-loader-in-matching-ISO',{archive_name:bytes(archive),image_name:bytes(image)},
                     'actual raw UDP retained runtime product'))
    assert len(variants)==25
    output.mkdir();results=[]
    for title,changes,reason in variants:
        case=output/title;case.mkdir()
        for original in originals:
            path=case/original;path.parent.mkdir(parents=True,exist_ok=True);path.symlink_to(source/original)
        manifest=json.loads(changes.get('manifest.json',(source/'manifest.json').read_bytes()))
        for name,changed in changes.items():
            if name!='manifest.json':manifest['products'][name]=hashlib.sha256(changed).hexdigest()
        changes=dict(changes,**{'manifest.json':encoded(manifest)})
        for name in changes:(case/name).unlink()
        archive=output/(title+'.zip')
        with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as bundle:
            for name,changed in changes.items():bundle.writestr(name,changed)
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():(case/name).write_bytes(bundle.read(name))
        try:verify(case)
        except ValueError as failure:
            assert str(failure)==reason,(title,str(failure),reason)
            results.append(dict(label=title,rejected=True,reason=reason,serialized_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
        else:raise AssertionError('counterfeit raw UDP evidence accepted: '+title)
        print('RAW_UDP_CONTROL_REJECTED '+title,flush=True)
    assert originals=={p.relative_to(source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
    report=dict(passed=True,positive=positive,serialized_reopened_controls=len(results),originals_unchanged=True,controls=results)
    (output/'results.json').write_bytes(encoded(report));return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report=run(args.directory,args.output)
    print('RAW_UDP_EVIDENCE_CONTROLS_PASS serialized_reopened='+str(report['serialized_reopened_controls'])+' originals_unchanged=1')

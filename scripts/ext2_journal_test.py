#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Recover real committed Linux journal records and exercise guest persistence."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from fetch import ROOT
from account_store_guest import fixture
from account_store_test import environment
from build_musl import compiler_args
from ext2_test import debugfs
from fixture_archive import archive_fixture

root = ROOT
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--directory', type=Path, default=ROOT / 'build/ext2-journal-guest')
parser.add_argument('--native-directory', type=Path, default=ROOT / 'build/ext2-journal-native')
parser.add_argument('--firmware', choices=('bios','uefi','both'), default='both')
parser.add_argument('--transport', choices=('modern','legacy','both'), default='both')
parser.add_argument('--provider', choices=('build','runtime','both'), default='both')
parser.add_argument('--linkage', choices=('static','dynamic','both'), default='both')
args = parser.parse_args()

output = args.directory.resolve()
assert output.is_relative_to((ROOT / 'build').resolve())
native = args.native_directory.resolve()
assert native.is_relative_to((ROOT / 'build').resolve())
producer = json.loads((native / 'receipt.json').read_text())
assert producer['passed'] and producer['terminal'] and producer['source_stable']
assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected
           for name, expected in producer['source_inputs'].items())
output.mkdir(exist_ok=False)
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
client = 'userspace/tests/fs/ext2-journal.c'
names = [client,'scripts/ext2_journal_test.py','scripts/ext2_journal_native_test.py','Makefile','dependencies.json','ports.lock.json','sources.lock.json','vendor/limine.h','boot/limine.conf']
names += [path.relative_to(root).as_posix() for base in ('kernel','userspace/init')
          for path in (root/base).rglob('*') if path.is_file() and path.suffix in ('.cpp','.hpp','.asm','.c','.h')]
names += [Path(module.__file__).resolve().relative_to(root).as_posix()
          for module in list(sys.modules.values()) if getattr(module,'__file__',None)
          and Path(module.__file__).resolve().is_relative_to(root/'scripts')]
sources = {name:digest(root/name) for name in names}
(output/'source-inputs.json').write_text(json.dumps(sources,indent=2)+'\n')
for name in sources:
    destination = output/'source'/name
    destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(root/name,destination)
subprocess.run(['make','-s','-j2','build/axiom64.elf','build/init','busybox'],cwd=root,check=True)
def build(provider, linkage, directory):
    program = directory/'ext2-journal'
    command = [*compiler_args(provider),'-std=c11','-O2','-g','-Wall','-Wextra','-Werror',*(['-static'] if linkage=='static' else []),str(root/client),'-o',str(program)]
    subprocess.run(command,cwd=root,env=environment(),check=True)
    headers = subprocess.check_output(['readelf','-W','-l',str(program)],text=True)
    dynamic = subprocess.check_output(['readelf','-W','-d',str(program)],text=True)
    if linkage=='static':
        assert 'INTERP' not in headers and '(NEEDED)' not in dynamic
    else:
        assert '/lib/ld-musl-x86_64.so.1' in headers and '(NEEDED)' in dynamic
        assert 'RPATH' not in dynamic and 'RUNPATH' not in dynamic
    return program,dict(command=command,binary_sha256=digest(program),headers=headers,dynamic=dynamic)
rows, error = [], None
try:
    for provider in ('build','runtime') if args.provider=='both' else (args.provider,):
        for linkage in ('static','dynamic') if args.linkage=='both' else (args.linkage,):
            for mode in ('read','write'):
                case = output/(provider+'-'+linkage+'-'+mode)
                case.mkdir()
                image = fixture(case,provider,linkage,program_builder=build,filename='ext2-journal',
                                command='/bin/ext2-journal '+mode)
                for label,size in (('1024',1024),('2048',2048),('4096',4096),('1024-untyped',1024)):
                    for firmware in ('bios','uefi') if args.firmware=='both' else (args.firmware,):
                        for transport in ('modern','legacy') if args.transport=='both' else (args.transport,):
                            phase = case/(label+'-'+firmware+'-'+transport)
                            phase.mkdir()
                            disk = phase/'disk.raw'
                            input_path = native/label/'crashed.raw.gz'
                            raw = gzip.decompress(input_path.read_bytes())
                            disk.write_bytes(raw)
                            command = ['qemu-system-x86_64','-machine','pc','-cpu','max','-m','256M','-nic','none',
                                       '-cdrom',str(image),'-display','none','-serial','stdio','-monitor','none','-no-reboot',
                                       '-device','isa-debug-exit,iobase=0xf4,iosize=0x04',
                                       '-drive','if=none,id=journal,format=raw,file='+str(disk),
                                       '-device','virtio-blk-pci,drive=journal,'+('disable-legacy=on' if transport=='modern' else 'disable-modern=on')]
                            if firmware=='uefi':
                                variables = phase/'VARS.fd'
                                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd',variables)
                                command += ['-drive','if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                            '-drive','if=pflash,format=raw,file='+str(variables)]
                            log = phase/'guest.log'
                            started = time.monotonic()
                            timed_out = False
                            with log.open('xb') as stream:
                                process = subprocess.Popen(command,cwd=root,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT)
                                try:
                                    process.wait(timeout=90)
                                except subprocess.TimeoutExpired:
                                    timed_out = True
                                    process.kill()
                                    process.wait()
                            text = log.read_text().replace('\r\n','\n')
                            marker = 'EXT2_JOURNAL_PASS mode='+mode+' block_size='+str(size)+' historical_bytes='+str(9*size-128)
                            row = dict(mode=mode,block_size=size,layout=label,firmware=firmware,transport=transport,provider=provider,linkage=linkage,
                                       command=command,returncode=process.returncode,timed_out=timed_out,
                                       elapsed_seconds=time.monotonic()-started,log_sha256=digest(log),
                                       input_compressed_sha256=digest(input_path),input_raw_sha256=hashlib.sha256(raw).hexdigest(),passed=False)
                            rows.append(row)
                            assert not timed_out and process.returncode==1
                            assert text.splitlines().count(marker)==1 and text.splitlines().count('AXIOM64_TESTS_PASS')==1
                            assert 'AXIOM64_EXIT status=0' in text and 'Firmware: '+firmware.upper() in text
                            assert not any(value in text for value in ('PANIC:','FAULT pid=','EXT2_JOURNAL_FAIL'))
                            check = subprocess.run(['e2fsck','-f','-n',str(disk)],capture_output=True,text=True)
                            (phase/'fsck.log').write_text(check.stdout+check.stderr)
                            assert check.returncode==0 and not re.search(r'count wrong|Fix\?|Clear\?|still has errors',check.stdout+check.stderr,re.I)
                            export = phase/'seed.bin'
                            debugfs(disk,'dump /seed '+str(export))
                            expected = bytes((index*31+17)&255 for index in range(9*size-128))+bytes((index*13+9)&255 for index in range(448))
                            if mode=='write':
                                expected += bytes((index*7+3)&255 for index in range(2*size+37))
                                extra = phase/'created.bin'
                                debugfs(disk,'dump /work/final '+str(extra))
                                assert extra.read_bytes()==expected[:size+97]
                            assert export.read_bytes()==expected
                            row.update(passed=True,fsck_returncode=0,historical_and_appended_bytes_verified=True)
                            row['retained_disk']=archive_fixture(disk,remove=True)
                            (output/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
                            print('EXT2_JOURNAL_GUEST_CELL_PASS '+provider+'/'+linkage+'/'+mode+'/'+label+'/'+firmware+'/'+transport,flush=True)
except BaseException as failure:
    error = repr(failure)
    raise
finally:
    stable = sources=={name:digest(root/name) for name in sources}
    (output/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
    (output/'receipt.json').write_text(json.dumps(dict(passed=error is None and stable,terminal=True,
        source_stable=stable,error=error,cells=len(rows),matrix_complete=all(getattr(args,name)=='both' for name in ('provider','linkage','firmware','transport')),timeout_seconds=90,
        host_repair_performed=False),indent=2)+'\n')
    if error:
        for disk in output.rglob('disk.raw'):
            archive_fixture(disk,remove=True)

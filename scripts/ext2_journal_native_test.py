#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare kernel journal records and recovery with native Linux filesystem tools."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

from fetch import ROOT
from ext2_test import debugfs, inode_offset
from fixture_archive import archive_fixture

root = ROOT
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--directory', type=Path, default=ROOT / 'build/ext2-journal-native')
args = parser.parse_args()

output = args.directory.resolve()
assert output.is_relative_to((ROOT / 'build').resolve())
output.mkdir(exist_ok=False)
inputs = ('kernel/fs/ext2/journal.cpp', 'kernel/include/fs/ext2/journal.hpp',
          'kernel/include/core/base.hpp', 'kernel/tests/fs/ext2_journal.cpp',
          'kernel/tests/fs/ext2_journal_volume.cpp', 'Makefile', 'scripts/ext2_journal_native_test.py',
          'scripts/ext2_test.py', 'scripts/fixture_archive.py')
inputs += tuple(Path(module.__file__).resolve().relative_to(ROOT).as_posix()
                for module in list(sys.modules.values()) if getattr(module, '__file__', None)
                and Path(module.__file__).resolve().is_relative_to(ROOT / 'scripts'))
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
sources = {name:digest(root / name) for name in inputs}
(output / 'source-inputs.json').write_text(json.dumps(sources,indent=2)+'\n')
for name in inputs:
    copy = output / 'source' / name
    copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / name, copy)
subprocess.run(['make', '-s', 'build/ext2-journal-volume-native'], cwd=ROOT, check=True)
binary = root / 'build/ext2-journal-volume-native'
rows = []
for label, size, inode_size, typed in (('1024',1024,128,True), ('2048',2048,256,True),
                                      ('4096',4096,256,True), ('1024-untyped',1024,128,False)):
    cell = output / label
    cell.mkdir()
    disk = cell / 'base.raw'
    with disk.open('xb') as destination:
        destination.truncate(64*1024*1024)
    command = ['mke2fs','-q','-F','-t','ext3','-b',str(size),'-I',str(inode_size),str(disk)]
    if not typed:
        command[-1:-1] = ['-O', '^filetype']
    process = subprocess.run(command,capture_output=True,text=True)
    assert process.returncode == 0
    (cell / 'mke2fs.log').write_text(process.stdout+process.stderr)
    old = bytes((index*31+17)&255 for index in range(9*size-128))
    appended = bytes((index*13+9)&255 for index in range(448))
    seed = cell / 'seed.bin'
    seed.write_bytes(old)
    debugfs(disk, 'write '+str(seed)+' /seed', write=True)
    strict = subprocess.run(['e2fsck','-f','-n',str(disk)],capture_output=True,text=True)
    assert strict.returncode == 0
    (cell / 'initial-fsck.log').write_text(strict.stdout+strict.stderr)
    raw = bytearray(disk.read_bytes())
    u32 = lambda offset: struct.unpack_from('<I',raw,offset)[0]
    first, blocks, per_group = u32(1044), u32(1028), u32(1056)
    journal = inode_offset(raw,8)
    length = u32(journal+4)//size
    def tree(pointer, depth):
        if not pointer:
            return
        assert first <= pointer < blocks
        if not depth:
            yield pointer
        else:
            for offset in range(0,size,4):
                yield from tree(u32(pointer*size+offset),depth-1)
    mapping = []
    for slot in range(15):
        mapping.extend(tree(u32(journal+40+4*slot),0 if slot<12 else slot-11))
    assert len(mapping) == length and len(set(mapping)) == length
    map_file = cell / 'journal-map.bin'
    map_file.write_bytes(struct.pack('<'+'I'*length,*mapping))
    journal_header = bytes(raw[mapping[0]*size:(mapping[0]+1)*size])
    assert struct.unpack_from('>II',journal_header)[0:2] == (0xc03b3998,4)
    (cell / 'linux-journal-header.bin').write_bytes(journal_header)
    number = int(re.search(r'Inode:\s+(\d+)',debugfs(disk,'stat /seed'))[1])
    inode = inode_offset(raw,number)
    assert u32(inode+4) == len(old) and u32(inode+40+9*4) == 0
    group_count = (blocks-first+per_group-1)//per_group
    chosen = None
    descriptors = (first+1)*size
    for group in range(group_count):
        bitmap = u32(descriptors+group*32)
        group_blocks = min(per_group,blocks-first-group*per_group)
        for bit in range(group_blocks):
            if not raw[bitmap*size+bit//8] & (1<<(bit%8)):
                chosen = first+group*per_group+bit,group,bitmap,bit
                break
        if chosen:
            break
    assert chosen
    added, group, bitmap, bit = chosen
    # The filesystem marks journal recovery required before accepting mutations.
    struct.pack_into('<I',raw,1120,u32(1120)|4)
    struct.pack_into('<H',raw,1082,struct.unpack_from('<H',raw,1082)[0]&~1)
    disk.write_bytes(raw)
    changed = bytearray(raw)
    tail = u32(inode+40+8*4)
    changed[tail*size+size-128:(tail+1)*size] = appended[:128]
    changed[added*size:(added+1)*size] = appended[128:]+bytes(size-320)
    struct.pack_into('<I',changed,inode+4,len(old)+len(appended))
    struct.pack_into('<I',changed,inode+40+9*4,added)
    struct.pack_into('<I',changed,inode+28,u32(inode+28)+size//512)
    changed[bitmap*size+bit//8] |= 1<<(bit%8)
    count = struct.unpack_from('<H',raw,descriptors+group*32+12)[0]
    struct.pack_into('<H',changed,descriptors+group*32+12,count-1)
    struct.pack_into('<I',changed,1036,u32(1036)-1)
    targets = [inode//size,bitmap,tail,added,(descriptors+group*32)//size,1024//size]
    assert len(set(targets)) == 6
    transaction = cell / 'transaction.bin'
    transaction.write_bytes(struct.pack('<I',len(targets))+b''.join(
        struct.pack('<I',block)+changed[block*size:(block+1)*size] for block in targets))
    crash = cell / 'crashed.raw'
    shutil.copyfile(disk,crash)
    command = [str(binary),'produce',str(crash),str(map_file),str(transaction),'13','after']
    process = subprocess.run(command,capture_output=True,text=True)
    (cell / 'producer.log').write_text(process.stdout+process.stderr)
    assert process.returncode == 1 and 'result=-5 calls=13 count=6' in process.stdout
    captured = crash.read_bytes()
    assert struct.unpack_from('<I',captured,inode+40+9*4)[0] == added
    assert not captured[bitmap*size+bit//8] & (1<<(bit%8))
    # A separate native checker copy is the interoperability oracle. Its
    # repairs are never used as the input to the module's recovery run.
    oracle = cell / 'checker-oracle.raw'
    recovered = cell / 'module-recovered.raw'
    shutil.copyfile(crash,oracle)
    shutil.copyfile(crash,recovered)
    oracle_run = subprocess.run(['e2fsck','-f','-y',str(oracle)],capture_output=True,text=True)
    (cell / 'oracle-replay.log').write_text(oracle_run.stdout+oracle_run.stderr)
    assert oracle_run.returncode in (0,1) and 'recovering journal' in oracle_run.stdout+oracle_run.stderr
    assert debugfs(oracle,'stat /seed')
    actual = subprocess.run([str(binary),'recover',str(recovered),str(map_file),str(transaction)],capture_output=True,text=True)
    (cell / 'module-replay.log').write_text(actual.stdout+actual.stderr)
    assert actual.returncode == 0 and 'RECOVERY_PASS staged=6' in actual.stdout
    for name, volume in (('oracle',oracle),('module',recovered)):
        check = subprocess.run(['e2fsck','-f','-n',str(volume)],capture_output=True,text=True)
        (cell / (name+'-strict-fsck.log')).write_text(check.stdout+check.stderr)
        assert check.returncode == 0
        export = cell / (name+'-seed.bin')
        debugfs(volume,'dump /seed '+str(export))
        assert export.read_bytes() == old+appended
    row = dict(passed=True,layout=label,block_size=size,inode_size=inode_size,journal_blocks=length,
               actual_linux_journal_header_sha256=digest(cell/'linux-journal-header.bin'),
               seed_inode=number,unallocated_referenced_block=added,cut_operation=13,
               durable_journal_committed=True,checkpoint_interrupted=True,
               module_recovery_host_repair=False,oracle_is_separate_native_checker_copy=True,
               native_oracle_repair_performed=True,historical_bytes_preserved=len(old),new_bytes=len(appended),
               inputs=dict(mapping=digest(map_file),transaction=digest(transaction),binary=digest(binary)),
               producer_command=command,archives={})
    for name in ('base','crashed','checker-oracle','module-recovered'):
        row['archives'][name] = archive_fixture(cell/(name+'.raw'),remove=True)
    rows.append(row)
    (output/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
    print('EXT2_JOURNAL_NATIVE_VOLUME_PASS block_size='+str(size),flush=True)
assert sources == {name:digest(root/name) for name in inputs}
receipt = dict(passed=True,terminal=True,source_stable=True,scope='native kernel-module interoperability; no guest mount claim',
               layouts=4,exact_allocation_pointer_cuts=4,strict_native_postchecks=8,
               module_host_repair_performed=False,oracle_is_separate_native_repaired_copy=True,
               binary_sha256=digest(binary),source_inputs=sources)
(output/'receipt.json').open('x').write(json.dumps(receipt,indent=2)+'\n')
print('EXT2_JOURNAL_NATIVE_VOLUME_MATRIX_PASS '+json.dumps(receipt),flush=True)

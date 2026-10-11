# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject damaged copies of actual successful file-capability evidence."""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from file_capabilities.common import digest
from file_capabilities.check import check
from file_capabilities.disk import attributes, inode_offset


def replace(path, data):
    path.unlink()
    path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/file-capabilities/guest')
    parser.add_argument('--metadata-directory', type=Path, default=ROOT / 'build/file-capabilities/metadata')
    args = parser.parse_args()
    source = args.directory.resolve()
    records = json.loads((source / 'results.json').read_text())
    original = next(row for row in records if row.get('filesystem') == 'ext2')
    count = 0
    def trial(name, operation, quick=True, fixture=None, original_record=None):
        nonlocal count
        with tempfile.TemporaryDirectory(prefix='filecap-damage-', dir=ROOT / 'build') as temporary:
            target = Path(temporary) / 'fixture'
            shutil.copytree(fixture or source, target, copy_function=os.link)
            selected = [copy.deepcopy(original_record or original)]
            replace(target / 'results.json', (json.dumps(selected) + '\n').encode())
            operation(target, selected[0])
            replace(target / 'results.json', (json.dumps(selected) + '\n').encode())
            try:
                check(target, quick=quick)
            except (ValueError, KeyError, StopIteration) as error:
                count += 1
                print('FILECAP_DAMAGE_REJECT name=' + name + ' reason=' + str(error), flush=True)
            else:
                raise AssertionError('damaged evidence was accepted: ' + name)
    def log_change(pattern, replacement):
        def operation(target, record):
            run = record['write']
            log = target / run['log']
            text, changed = re.subn(pattern, replacement, log.read_text(), count=1, flags=re.M)
            if changed != 1:
                raise AssertionError('actual damage fixture lacks the selected receipt')
            replace(log, text.encode())
            run['log_sha256'] = digest(log)
        return operation
    trial('actual-permitted', log_change(r'^(FILECAP_EXEC_RECEIPT name=effective .*?permitted=)10000000002', r'\g<1>2'))
    trial('actual-effective', log_change(r'^(FILECAP_EXEC_RECEIPT name=permitted .*?effective=)0', r'\g<1>2'))
    trial('actual-ambient', log_change(r'^(FILECAP_EXEC_RECEIPT name=ambient-empty .*?ambient=)0', r'\g<1>2'))
    trial('actual-bounding', log_change(r'^(FILECAP_EXEC_RECEIPT name=bounded-permitted .*?bounding=)ffffffffff', r'\g<1>1ffffffffff'))
    trial('actual-setuid', log_change(r'^(FILECAP_EXEC_RECEIPT name=setuid-file .*?euid=)0', r'\g<1>1001'))
    trial('actual-secure', log_change(r'^(FILECAP_EXEC_RECEIPT name=effective .*?secure=)1', r'\g<1>0'))
    trial('synchronized-dumpability', log_change(r'^(FILECAP_EXEC_RECEIPT name=inheritable .*?)dumpable=1(.*?)expected_dumpable=normal',
                                               r'\g<1>dumpable=0\g<2>expected_dumpable=restricted'))
    trial('synchronized-errno', log_change(r'^(FILECAP_OBSERVATION .*?name=unprivileged-setfcap )result=-1 errno=1 expected=-1 expected_errno=1',
                                         r'\g<1>result=0 errno=0 expected=0 expected_errno=0'))
    trial('failed-exec-state', log_change(r'^(FILECAP_FAILED_CREDENTIAL_RECEIPT name=bounded-denied stage=after .*?permitted=)0', r'\g<1>2'))
    trial('missing-service', log_change(r'^FILECAP_EXEC_RECEIPT name=effective .+\n', ''))
    trial('duplicated-service', log_change(r'^(FILECAP_EXEC_RECEIPT name=effective .+)$', r'\g<1>\n\g<1>'))
    trial('missing-observation', log_change(r'^FILECAP_OBSERVATION .*?name=fgetxattr .+\n', ''))
    trial('tool-status', log_change(r'^(FILECAP_TOOL_RECEIPT name=setcap-static )status=0 expected=0', r'\g<1>status=1 expected=1'))
    trial('deadline', lambda target, row: row['write'].update(elapsed_ns=130000000000))
    trial('exit-status', lambda target, row: row['write'].update(returncode=3))
    def corrupt(target, record):
        path = target / 'inputs/build/file-capabilities-static'
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        replace(path, data)
    trial('captured-client', corrupt)
    def synchronized_client(target, record):
        linkage = record['linkage']
        name = 'build/file-capabilities-' + linkage
        path = target / 'inputs' / name
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        replace(path, data)
        manifest = json.loads((target / 'inputs.json').read_text())
        manifest['files'][name] = digest(path)
        replace(target / 'inputs.json', (json.dumps(manifest) + '\n').encode())
    trial('synchronized-client-iso', synchronized_client, quick=False)
    metadata = args.metadata_directory.resolve()
    records = json.loads((metadata / 'results.json').read_text())
    shared = next(row for row in records if row['kind'] == 'shared')
    recovered = next(row for row in records if row['kind'] == 'write-error')
    def attribute_damage(path, index, suffix):
        def operation(target, record):
            disk = target / record['disk']
            data = bytearray(disk.read_bytes())
            text = subprocess.check_output(['/usr/sbin/debugfs', '-R', 'stat ' + path, str(disk)], stderr=subprocess.DEVNULL).decode()
            number = int(re.search(r'Inode:\s+(\d+)', text)[1])
            _, header = attributes(data, inode_offset(data, number))
            block = 1024 << struct.unpack_from('<I', data, 1048)[0]
            start = header['block'] * block
            at = start + 32
            while data[at:at + 4] != bytes(4):
                length = data[at]
                if data[at + 1] == index and data[at + 16:at + 16 + length] == suffix:
                    value = struct.unpack_from('<H', data, at + 2)[0]
                    data[start + value] ^= 1
                    break
                at += (16 + length + 3) & ~3
            else:
                raise AssertionError('actual metadata damage fixture lacks attribute')
            replace(disk, data)
            record['disk_sha256'] = digest(disk)
        return operation
    trial('synchronized-recovery-attributes', attribute_damage('/fault', 1, b'unrelated'),
          fixture=metadata, original_record=recovered)
    trial('synchronized-shared-opaque', attribute_damage('/beta', 9, b'opaque-extra'),
          fixture=metadata, original_record=shared)
    def control_damage(target, record):
        disk = target / record['disk']
        data = disk.read_bytes()
        value = b'unrelated ordinary file bytes\0\xff\n'
        if data.count(value) != 1:
            raise AssertionError('actual unrelated payload is not unique')
        replace(disk, data.replace(value, b'X' + value[1:], 1))
        record['disk_sha256'] = digest(disk)
    trial('synchronized-unrelated-file', control_damage, fixture=metadata, original_record=shared)
    print('FILECAP_DAMAGE_PASS cases=' + str(count), flush=True)


if __name__ == '__main__':
    main()

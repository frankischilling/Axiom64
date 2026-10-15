# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay an actual failed-device export and reject changed provisional authority."""
import binascii
import copy
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import account_logbook_rotation_ext2 as acceptance


def file_metadata(data, mode=0o600):
    return dict(kind='regular', mode=mode, uid=0, gid=0, bytes=len(data), links=1)


def default_state():
    data = bytearray(struct.pack('<IIIIQQQ', 0x53423641, 1, 40, 0, 1, 0, 0))
    struct.pack_into('<I', data, 12, binascii.crc32(data))
    return bytes(data)


def main(verifier=acceptance.verify):
    fixture = json.loads((Path(__file__).parent / 'fixtures/account-rotation-provisional.json').read_text())
    assert fixture['origin']['actual_virtio_eio'] and fixture['origin']['request'] == 33
    original = {name: bytes.fromhex(data) for name, data in fixture['files'].items()}
    before = {name: bytes.fromhex(data) for name, data in fixture['before'].items()}
    metadata = fixture['metadata']
    archive = 'archive-0000000000000001'
    journal = archive + '/journal'

    def check(files, records):
        return verifier(files, records, before, recovered=False)

    assert original[journal] == original['journal']
    assert check(original, metadata)['provisional_archive']
    empty, empty_metadata = copy.deepcopy((original, metadata))
    del empty[journal]
    del empty_metadata[journal]
    assert check(empty, empty_metadata)['provisional_archive']
    complete, complete_metadata = copy.deepcopy((original, metadata))
    for name in acceptance.ARCHIVE_FILES:
        key = archive + '/' + name
        data = default_state() if name == 'state' else original[name]
        complete[key] = data
        complete_metadata[key] = file_metadata(data, 0o644 if name == 'wtmp' else 0o600)
    assert check(complete, complete_metadata)['provisional_archive']

    negatives = []

    def reject(label, mutate):
        files, records = copy.deepcopy((original, metadata))
        mutate(files, records)
        try:
            check(files, records)
        except (AssertionError, ValueError):
            negatives.append(label)
            return
        raise AssertionError('changed storage proof accepted: ' + label)

    def shortened(files, records):
        files[journal] = files[journal][:-1]
        records[journal]['bytes'] = len(files[journal])

    def corrupted(files, records):
        data = bytearray(files[journal])
        data[-1] ^= 1
        files[journal] = bytes(data)

    def unknown(files, records):
        name = archive + '/unproven'
        files[name] = b''
        records[name] = file_metadata(b'')

    def future(files, records):
        new = 'archive-0000000000000002'
        files[new + '/journal'] = files.pop(journal)
        records[new] = records.pop(archive)
        records[new + '/journal'] = records.pop(journal)

    def state_mismatch(files, records):
        data = bytearray(default_state())
        struct.pack_into('<Q', data, 16, 2)
        struct.pack_into('<I', data, 12, 0)
        struct.pack_into('<I', data, 12, binascii.crc32(data))
        key = archive + '/state'
        files[key] = bytes(data)
        records[key] = file_metadata(data)

    reject('truncated_journal_with_synchronized_size', shortened)
    reject('changed_journal', corrupted)
    reject('unproven_member_with_complete_metadata', unknown)
    reject('future_archive_with_consistent_names', future)
    reject('well_checksummed_wrong_generation', state_mismatch)
    reject('foreign_owner', lambda files, records: records[journal].update(uid=70000))
    reject('public_journal_mode', lambda files, records: records[journal].update(mode=0o644))
    reject('hardlinked_journal', lambda files, records: records[journal].update(links=2))
    reject('missing_metadata', lambda files, records: records.pop(journal))
    reject('unknown_empty_directory', lambda files, records: records.update(
        unrelated=dict(kind='directory', mode=0o755, uid=0, gid=0, bytes=1024, links=2)))
    print('ACCOUNT_ROTATION_STORAGE_CHECKER_PASS actual_device_fixture=1 positive_cases=3 negative_cases=' +
          str(len(negatives)), flush=True)


if __name__ == '__main__':
    main()

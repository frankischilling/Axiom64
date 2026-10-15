# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe Linux journal replay on a private copy, never on a guest input."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


@contextmanager
def journal_observation(disk, directory):
    disk, directory = Path(disk), Path(directory)
    original = disk.lstat()
    if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
        raise ValueError('the journal oracle requires a regular owned fixture')
    with disk.open('rb') as stream:
        stream.seek(1024)
        header = stream.read(1024)
    if (len(header) != 1024 or struct.unpack_from('<H', header, 56)[0] != 0xef53 or
            not struct.unpack_from('<I', header, 92)[0] & 4):
        raise ValueError('the journal oracle requires an internal journal')
    expected = digest(disk)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    record = dict(passed=False, journal_only=True, observation_copy_only=True,
                  guest_input_sha256=expected, bytes=original.st_size)
    try:
        with tempfile.TemporaryDirectory(prefix='axiom64-account-journal-oracle-', dir='/tmp') as temporary:
            copy = Path(temporary) / 'observation.raw'
            shutil.copyfile(disk, copy)
            if digest(copy) != expected:
                raise RuntimeError('journal oracle staging changed the observed bytes')
            tool = Path(shutil.which('e2fsck') or '/usr/sbin/e2fsck')
            command = [str(tool), '-y', '-E', 'journal_only', str(copy)]
            record.update(command=command, tool_sha256=digest(tool))
            result = subprocess.run(command, capture_output=True, text=True, timeout=120,
                                    stdin=subprocess.DEVNULL)
            log = directory / 'journal-oracle.log'
            with log.open('x') as stream:
                stream.write(result.stdout + result.stderr)
            record.update(returncode=result.returncode, log_sha256=digest(log))
            if result.returncode not in (0, 1):
                raise RuntimeError('Linux journal-only replay of the observation copy failed')
            if copy.stat().st_size != original.st_size:
                raise RuntimeError('journal oracle changed the observation geometry')
            record.update(observation_sha256=digest(copy), observation_modified=digest(copy) != expected)
            # This temporary path is used only by native readers. It is removed
            # before the caller can start recovery with the original guest disk.
            yield copy, record
            record['passed'] = True
    except BaseException as error:
        record['error'] = repr(error)
        raise
    finally:
        unchanged = identity(disk.lstat()) == identity(original) and digest(disk) == expected
        record.update(guest_input_unchanged=unchanged, terminal=True)
        record['passed'] = record['passed'] and unchanged
        with (directory / 'journal-oracle.json').open('x') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
        if not unchanged:
            raise RuntimeError('actual guest input changed during native observation')

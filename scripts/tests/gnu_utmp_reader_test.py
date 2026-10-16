#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Execute the pinned GNU reader, move/relink its kit, and reject altered inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_gnu_utmp_reader as reader


def entry(kind, pid=0, user=b''):
    # Linux x86-64 public utmp layout, independent of the project journal codec.
    value = bytearray(384)
    struct.pack_into('<h', value, 0, kind)
    struct.pack_into('<i', value, 4, pid)
    value[8:13] = b'pts/1'
    value[44:44 + len(user)] = user
    struct.pack_into('<iii', value, 336, pid, 1700000000, 123456)
    return bytes(value)


def fixtures(directory):
    directory.mkdir()
    (directory / 'utmp').write_bytes(entry(8, 124))
    (directory / 'wtmp').write_bytes(entry(2) + entry(7, 123, b'alice') + entry(8, 123) +
                                   entry(7, 124, b'alice') + entry(8, 124))
    (directory / 'btmp').write_bytes(entry(6, 125, b'missing'))


def execute(command, log, expected):
    result = subprocess.run(command, capture_output=True, timeout=30)
    log.write_bytes(result.stdout + result.stderr)
    assert result.returncode == expected, (command, result.returncode, log.read_text())
    return dict(command=command, returncode=result.returncode, log=log.name, sha256=reader.digest(log))


def public_archive(source_archive, out):
    """Execute and relink the actual published kit, independently of its producer."""
    archive_sha256 = reader.digest(source_archive)
    exported = out / 'exported-kit'
    exported.mkdir()
    prefix = 'verification/gnu-utmp-reader/'
    members = set()
    with tarfile.open(source_archive, 'r:*') as archive:
        for member in archive:
            if not member.name.startswith(prefix):
                continue
            relative = PurePosixPath(member.name.removeprefix(prefix))
            assert relative.parts and not relative.is_absolute() and '..' not in relative.parts
            assert member.isfile() and member.name not in members and member.size <= 64 * 1024 * 1024
            members.add(member.name)
            target = exported.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('wb') as destination:
                shutil.copyfileobj(source, destination)
            target.chmod(member.mode & 0o777)
        manifest = json.loads((exported / 'manifest.json').read_text())
        assert manifest['pin_sha256'] == reader.digest(reader.PIN)
        assert manifest['source_sha256'] == reader.digest(reader.CLIENT)
        assert manifest['recipe_sha256'] == reader.digest(Path(reader.__file__))
        assert manifest['publication']['recipe_sha256'] == reader.digest(reader.ROOT / 'scripts/sources.py')
        assert members == {prefix + name for name in [*manifest['products'], 'manifest.json']}
        assert manifest['symlinks'] == {}
        for name, expected in manifest['products'].items():
            assert reader.digest(exported / name) == expected, name
        # Bind the kit to the exact application, recipes and pinned upstream
        # files in this source artifact, rather than to a live producer cache.
        bindings = {
            'Axiom64/userspace/tests/security/account-login-libc.c': manifest['source_sha256'],
            'Axiom64/scripts/build_gnu_utmp_reader.py': manifest['recipe_sha256'],
            'Axiom64/scripts/sources.py': manifest['publication']['recipe_sha256'],
            'ports/gnu-utmp-reader/inputs.json': manifest['pin_sha256'],
        }
        pin = json.loads(archive.extractfile('ports/gnu-utmp-reader/inputs.json').read())
        upstream = [*pin['packages'], *(row for origin in pin['sources'].values() for row in origin['files'])]
        bindings.update({'ports/gnu-utmp-reader/' + row['name']: row['sha256'] for row in upstream})
        bindings.update({'ports/gnu-utmp-reader/' + name: expected for name, expected in pin['notices'].items()})
        for name, expected in bindings.items():
            member = archive.getmember(name)
            assert member.isfile()
            with archive.extractfile(member) as source:
                assert hashlib.file_digest(source, 'sha256').hexdigest() == expected, name
        for name, expected in pin['notices'].items():
            assert reader.digest(exported / 'licenses' / name) == expected, name
    assert str(reader.ROOT) not in (exported / 'manifest.json').read_text()
    moved = out / 'moved-kit'
    exported.rename(moved)
    valid = out / 'records'
    fixtures(valid)
    binary = moved / 'account-login-libc'
    rows = [execute([str(binary), str(valid)], out / 'published.log', 0)]
    marker = 'ACCOUNT_LOGIN_LIBC_PASS utmp=1 wtmp=5 btmp=1 users=2 dead=2 boot=1'
    assert marker in (out / 'published.log').read_text()
    relinked = moved / 'reader-relinked'
    rows.append(execute(['sh', str(moved / 'relink.sh'), str(relinked)], out / 'public-relink.log', 0))
    assert reader.digest(relinked) == reader.digest(binary)
    rows.append(execute([str(relinked), str(valid)], out / 'public-moved.log', 0))
    assert marker in (out / 'public-moved.log').read_text()
    (valid / 'btmp').write_bytes(entry(7, 125, b'wrong'))
    rows.append(execute([str(relinked), str(valid)], out / 'public-damaged.log', 1))
    assert 'ACCOUNT_LOGIN_LIBC_FAIL' in (out / 'public-damaged.log').read_text()
    for name, expected in manifest['products'].items():
        assert reader.digest(moved / name) == expected, name
    assert reader.digest(source_archive) == archive_sha256
    result = dict(passed=True, controls=4, executions=rows,
                  source_archive_sha256=archive_sha256, archived_source_bindings=len(bindings),
                  kit_files=len(members), public_manifest_sha256=reader.digest(moved / 'manifest.json'),
                  relinked_sha256=reader.digest(relinked))
    (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print('GNU_UTMP_READER_PUBLIC_ARCHIVE_PASS controls=4 moved_relink=identical', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path,
                        help='validate the kit extracted from the actual corresponding-source artifact')
    args = parser.parse_args()
    out = args.directory.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = {str(path.relative_to(reader.ROOT)): reader.digest(path) for path in
              (Path(__file__), Path(reader.__file__), reader.PIN, reader.CLIENT)}
    (out / 'source-inputs.json').write_text(json.dumps(source, indent=2) + '\n')
    if args.source_archive:
        public_archive(args.source_archive.resolve(), out)
        assert source == {name: reader.digest(reader.ROOT / name) for name in source}
        return
    binary, inputs = reader.build(out / 'original-kit')
    valid = out / 'records'
    fixtures(valid)
    rows = [execute([str(binary), str(valid)], out / 'original.log', 0)]
    assert 'ACCOUNT_LOGIN_LIBC_PASS utmp=1 wtmp=5 btmp=1 users=2 dead=2 boot=1' in (out / 'original.log').read_text()
    moved = out / 'moved-kit'
    shutil.copytree(binary.parent, moved, symlinks=True)
    rows.append(execute(['sh', str(moved / 'relink.sh'), str(moved / 'reader-relinked')], out / 'relink.log', 0))
    assert reader.digest(moved / 'reader-relinked') == reader.digest(binary)
    rows.append(execute([str(moved / 'reader-relinked'), str(valid)], out / 'moved.log', 0))
    # A malformed projected record must be rejected by the executed GNU client.
    (valid / 'btmp').write_bytes(entry(7, 125, b'wrong'))
    rows.append(execute([str(moved / 'reader-relinked'), str(valid)], out / 'damaged.log', 1))
    assert 'ACCOUNT_LOGIN_LIBC_FAIL' in (out / 'damaged.log').read_text()
    current_output = reader.OUTPUT
    cache = out / 'private-cache'
    producer = current_output / inputs['identity']
    shutil.copytree(producer, cache / inputs['identity'], symlinks=True, copy_function=os.link)
    archive = cache / inputs['identity'] / 'sysroot/usr/lib/x86_64-linux-gnu/libc.a'
    archive.unlink()
    shutil.copyfile(producer / 'sysroot/usr/lib/x86_64-linux-gnu/libc.a', archive)
    with archive.open('r+b') as stream:
        original = stream.read(1)
        stream.seek(0)
        stream.write(bytes([original[0] ^ 1]))
    reader.OUTPUT = cache
    try:
        reader.ensure()
    except RuntimeError as error:
        assert str(error).startswith('GNU reader cached product differs: ')
        rejected_cache = str(error)
    else:
        raise AssertionError('changed static library was accepted')
    finally:
        reader.OUTPUT = current_output
    pin_directory = out / 'private-pin'
    shutil.copytree(reader.PIN.parent, pin_directory)
    notice = pin_directory / 'glibc-COPYING.LIB'
    notice.write_bytes(notice.read_bytes() + b'damaged\n')
    current_pin = reader.PIN
    reader.PIN = pin_directory / 'inputs.json'
    try:
        reader.pins()
    except RuntimeError as error:
        assert str(error).startswith('GNU reader license notice differs: ')
        rejected_notice = str(error)
    else:
        raise AssertionError('changed license notice was accepted')
    finally:
        reader.PIN = current_pin
    assert source == {name: reader.digest(reader.ROOT / name) for name in source}
    result = dict(passed=True, controls=6, executions=rows, reader=inputs,
                  changed_archive_rejected=rejected_cache, changed_notice_rejected=rejected_notice,
                  relinked_sha256=reader.digest(moved / 'reader-relinked'))
    (out / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print('GNU_UTMP_READER_NATIVE_PASS controls=6 moved_relink=identical', flush=True)


if __name__ == '__main__':
    main()

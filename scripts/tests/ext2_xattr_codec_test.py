# SPDX-License-Identifier: GPL-3.0-or-later
"""Check actual ext2 attribute blocks and generated replacements with e2fsprogs."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
output = ROOT / 'build/ext2-xattr-codec'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    output.mkdir(parents=True, exist_ok=True)
    tools = {name: shutil.which(name) or '/usr/sbin/' + name for name in ('mke2fs', 'debugfs', 'e2fsck')}
    version = subprocess.run([tools['debugfs'], '-V'], capture_output=True, text=True, check=True)
    commands, rows = [], []
    regular = output / 'regular'
    regular.write_bytes(b'ordinary file bytes\n')
    binary = output / 'binary'
    binary.write_bytes(bytes((0, 255, 1, 2)))
    capability = output / 'capability'
    capability.write_bytes(struct.pack('<5I', 0x02000001, 1 << 10, 0, 0, 0))

    def debug(image, command, write=False):
        process = subprocess.run([tools['debugfs'], *(['-w'] if write else []), '-R', command, str(image)],
                                 capture_output=True, text=True, check=True)
        commands.append(dict(image=image.name, command=command, stdout=process.stdout, stderr=process.stderr))
        return process.stdout

    def quote(path):
        return '"' + str(path).replace('\\', '\\\\').replace('"', '\\"') + '"'

    for size in (1024, 2048, 4096):
        image = output / f'seed-{size}.img'
        with image.open('wb') as stream:
            stream.truncate(16 * 1024 * 1024)
        process = subprocess.run([tools['mke2fs'], '-q', '-t', 'ext2', '-b', str(size), '-I', '128', '-F', str(image)],
                                 capture_output=True, text=True, check=True)
        commands.append(dict(image=image.name, command='mke2fs', stdout=process.stdout, stderr=process.stderr))
        debug(image, 'write ' + quote(regular) + ' /target', True)
        for command in ('ea_set /target user.alpha one', 'ea_set -f ' + quote(binary) + ' /target user.binary',
                        'ea_set /target trusted.private secret', 'ea_set -f ' + quote(capability) + ' /target security.capability',
                        'ea_set /target user.é utf8'):
            debug(image, command, True)
        stat = debug(image, 'stat /target')
        match = re.search(r'File ACL:\s*(\d+)', stat)
        assert match and int(match[1])
        block = int(match[1])
        with image.open('rb') as stream:
            stream.seek(block * size)
            data = stream.read(size)
        seed = output / f'seed-{size}.bin'
        seed.write_bytes(data)
        check = subprocess.run([tools['e2fsck'], '-fn', str(image)], capture_output=True, text=True)
        (output / f'seed-{size}-fsck.log').write_text(check.stdout + check.stderr)
        assert check.returncode == 0
        rows.append(dict(block_size=size, block=block, image=image.name, source_block=seed.name,
                         image_sha256=digest(image), source_sha256=digest(seed), initial_fsck=0))
    process = subprocess.run([str(ROOT / 'build/ext2-xattr-codec-test'),
                              *(str(output / row['source_block']) for row in rows)],
                             capture_output=True, text=True)
    (output / 'host.log').write_text(process.stdout + process.stderr)
    print(process.stdout, end='', flush=True)
    assert process.returncode == 0, process.stderr
    assert 'EXT2_XATTR_CODEC_PASS actual_blocks=3 malformed_cases=51 ' in process.stdout
    for row in rows:
        image = output / row['image']
        modified = output / f'generated-{row["block_size"]}.img'
        shutil.copy2(image, modified)
        data = (output / (row['source_block'] + '.generated')).read_bytes()
        assert len(data) == row['block_size']
        with modified.open('r+b') as stream:
            stream.seek(row['block'] * row['block_size'])
            stream.write(data)
        check = subprocess.run([tools['e2fsck'], '-fn', str(modified)], capture_output=True, text=True)
        (output / f'generated-{row["block_size"]}-fsck.log').write_text(check.stdout + check.stderr)
        assert check.returncode == 0, check.stdout + check.stderr
        for name, expected in (('user.alpha', b'changed'), ('user.new', binary.read_bytes()),
                               ('trusted.private', b'secret'), ('security.capability', capability.read_bytes()),
                               ('user.é', b'utf8')):
            target = output / f'export-{row["block_size"]}-{name}'
            debug(modified, 'ea_get -f ' + quote(target) + ' /target ' + name)
            assert target.read_bytes() == expected
        names = debug(modified, 'ea_list /target')
        assert 'user.binary' not in names and 'user.new' in names
        row.update(generated_sha256=digest(modified), generated_block_sha256=hashlib.sha256(data).hexdigest(),
                   generated_fsck=0, independently_exported_attributes=5)
    (output / 'results.json').write_text(json.dumps(dict(passed=True, e2fsprogs=version.stdout + version.stderr,
        blocks=rows, malformed_cases=51, commands=commands), indent=2) + '\n')
    print('EXT2_XATTR_EXTERNAL_PASS block_sizes=3 original_fsck=3 generated_fsck=3 independently_exported=15', flush=True)


if __name__ == '__main__':
    main()

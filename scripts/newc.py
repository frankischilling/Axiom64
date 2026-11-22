# SPDX-License-Identifier: GPL-3.0-or-later
"""Write a deterministic newc archive from guest paths, modes, and bytes."""


def write_cpio(destination, files):
    with destination.open('wb') as output:
        for inode, (name, (mode, payload)) in enumerate([*sorted(files.items()), ('TRAILER!!!', (0, b''))], 1):
            encoded = name.encode() + b'\0'
            fields = [inode, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(encoded), 0]
            output.write(b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded)
            output.write(bytes(-output.tell() % 4))
            output.write(payload)
            output.write(bytes(-output.tell() % 4))

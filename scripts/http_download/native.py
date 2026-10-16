# SPDX-License-Identifier: GPL-3.0-or-later
"""Give native comparisons a real ordinary account in their private namespace."""
import os
from pathlib import Path
import subprocess
import sys


def command(directory, arguments):
    """Keep host account policy out of synthetic-UID application comparisons."""
    home = directory / 'output'
    accounts = {
        'passwd': 'root:x:0:0:root:/root:/bin/sh\n'
                  'axiom64-fixture:x:60011:60011:Download fixture:' + str(home) + ':/bin/sh\n',
        'group': 'root:x:0:\naxiom64-fixture:x:60011:\n',
    }
    for name, data in accounts.items():
        path = directory / name
        with path.open('x') as stream:
            stream.write(data)
        path.chmod(0o644)
    return ['unshare', '--mount', '--propagation', 'private', '--pid', '--fork',
            '--kill-child', '--mount-proc', '--', sys.executable,
            str(Path(__file__).resolve()), str(directory), *arguments]


def main():
    directory = Path(sys.argv[1]).resolve(strict=True)
    if os.geteuid() != 0 or not directory.name.startswith('axiom64-http-client-'):
        raise RuntimeError('native account binding requires the owned root fixture')
    for name in ('passwd', 'group'):
        subprocess.run(['mount', '--bind', str(directory / name), '/etc/' + name], check=True)
    os.execvp(sys.argv[2], sys.argv[2:])


if __name__ == '__main__':
    main()

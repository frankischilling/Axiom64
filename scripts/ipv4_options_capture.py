# SPDX-License-Identifier: GPL-3.0-or-later
"""Capture Linux IPv4 option setter/query observations for both credentials."""
import argparse
import gzip
import json
import os
from pathlib import Path

from fetch import ROOT
from ipv4_options.corpus import capture
from tcp6.inputs import digest


def ordinary_capture():
    reader, writer = os.pipe()
    child = os.fork()
    if not child:
        os.close(reader)
        try:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            with os.fdopen(writer, 'w') as stream:
                json.dump(capture(), stream)
        except BaseException:
            os._exit(1)
        os._exit(0)
    os.close(writer)
    with os.fdopen(reader) as stream:
        data = stream.read()
    waited, status = os.waitpid(child, 0)
    if waited != child or not os.WIFEXITED(status) or os.WEXITSTATUS(status):
        raise ValueError('ordinary native option observation failed')
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/ipv4-options-native.json.gz')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('root is required for both capability profiles')
    root, ordinary = capture(), ordinary_capture()
    if not (int(root['effective_capabilities'], 16) & (1 << 13)) or int(ordinary['effective_capabilities'], 16):
        raise ValueError('actual root CAP_NET_RAW and ordinary capability profiles required')
    if root['vectors'] != 7110 or ordinary['vectors'] != 7110:
        raise ValueError('incomplete actual native corpus')
    record = dict(kernel=root['kernel'], root=root['rows'], ordinary=ordinary['rows'],
                  profiles=[{key: value for key, value in profile.items() if key != 'rows'}
                            for profile in (root, ordinary)],
                  sources={name: digest(ROOT / name) for name in
                           ('scripts/ipv4_options_capture.py', 'scripts/ipv4_options/corpus.py')})
    data = (json.dumps(record, indent=2) + '\n').encode()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as stream:
        stream.write(gzip.compress(data, mtime=0) if args.output.suffix == '.gz' else data)
    print(json.dumps(dict(kernel=root['kernel'], vectors_each=7110, packets_sent=0,
                          output=str(args.output), sha256=digest(args.output))))


if __name__ == '__main__':
    main()

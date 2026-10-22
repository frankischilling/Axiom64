# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind local extension observations to the original full-client execution."""
import hashlib
import json
from pathlib import Path


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_execution(path, native, source, source_hash):
    def require(value, reason):
        if not value:
            raise ValueError(reason)

    directory = Path(path).parent
    receipt = json.loads((directory / ('receipt.json' if native else 'result.json')).read_text())
    require(receipt['returncode'] == (0 if native else 1) and
            receipt['source_products_unchanged' if native else 'products_sources_unchanged'],
            'completed original full client with unchanged inputs')
    if native:
        before = json.loads((directory / 'preexecution.json').read_text())
        require(before['source_sha256'][source] == source_hash,
                'actual native application contains the source-bound probe')
        for number, command in enumerate(before['command']):
            require(digest(directory / 'products' / f'{number}-{Path(command).name}') ==
                    before['product_sha256'][command], 'actual original native program and loader')
    else:
        linkage = directory.name.split('-', 1)[0]
        before = json.loads((directory.parent / (linkage + '-inputs.json')).read_text())
        require(before['sources'][source] == source_hash,
                'actual guest application contains the source-bound probe')

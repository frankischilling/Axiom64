# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify the pinned public trust bundle and retain its exact Mozilla source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tarfile
import tempfile

from fetch import LOCK, ROOT, fetch
from ports import download


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_inputs():
    dependency = LOCK['ca_bundle']
    bundle = fetch('ca_bundle')
    result = [bundle]
    for field, name in (('source', 'certdata.txt'), ('license', 'MPL-2.0.txt')):
        path = download(dependency[field + '_url'], ROOT / 'downloads/sources/ca-bundle' / name)
        if digest(path) != dependency[field + '_sha256']:
            raise RuntimeError('CA bundle input checksum differs: ' + name)
        result.append(path)
    return 'ca-bundle', result


def certificates(data):
    blocks = re.findall(rb'-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----', data, re.S)
    if (data.count(b'-----BEGIN CERTIFICATE-----') != len(blocks) or
        data.count(b'-----END CERTIFICATE-----') != len(blocks)):
        raise RuntimeError('CA bundle has incomplete PEM records')
    values = [ssl.PEM_cert_to_DER_cert(block.decode('ascii')) for block in blocks]
    if not values or len(set(values)) != len(values):
        raise RuntimeError('CA bundle has empty or repeated certificates')
    return set(values)


def ensure():
    dependency = LOCK['ca_bundle']
    epoch = dependency['source_date_epoch']
    if type(epoch) is not int or not 0 < epoch < 2**63:
        raise RuntimeError('CA bundle publication epoch is invalid')
    _, paths = source_inputs()
    bundle, source, license_file = paths
    text = bundle.read_text()
    if re.findall(r'^## SHA256: ([0-9a-f]{64})$', text, re.M) != [dependency['source_sha256']]:
        raise RuntimeError('CA bundle does not bind the pinned Mozilla source')
    expected = certificates(bundle.read_bytes())
    if len(expected) != dependency['certificates']:
        raise RuntimeError('CA bundle certificate inventory differs')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(bundle))
    if set(context.get_ca_certs(binary_form=True)) != expected:
        raise RuntimeError('TLS library did not load every pinned CA certificate')
    archive = fetch('curl')
    with tarfile.open(archive) as stream:
        script = stream.extractfile('curl-' + LOCK['curl']['version'] + '/scripts/mk-ca-bundle.pl').read()
    identity_inputs = dict(dependency=dependency, curl_archive_sha256=digest(archive),
                           generator_sha256=hashlib.sha256(script).hexdigest(),
                           recipe_sha256=digest(Path(__file__)))
    identity = hashlib.sha256(json.dumps(identity_inputs, sort_keys=True).encode()).hexdigest()
    destination = ROOT / 'build/ca-bundle' / identity
    manifest = destination / 'manifest.json'
    if manifest.exists():
        record = json.loads(manifest.read_text())
        if record['identity_inputs'] != identity_inputs:
            raise RuntimeError('CA bundle cached identity differs')
        for name, expected_hash in record['products'].items():
            if digest(destination / name) != expected_hash:
                raise RuntimeError('CA bundle cached product changed: ' + name)
        return destination
    if destination.exists():
        raise RuntimeError('incomplete CA bundle proof retained: ' + str(destination))
    destination.mkdir(parents=True)
    # Conversion is offline and uses the authenticated release's original tool.
    with tempfile.TemporaryDirectory(prefix='axiom64-ca-conversion-') as temporary:
        work = Path(temporary)
        shutil.copy2(source, work / 'certdata.txt')
        os.utime(work / 'certdata.txt', (epoch, epoch))
        tool = work / 'mk-ca-bundle.pl'
        tool.write_bytes(script)
        converted = work / 'converted.pem'
        # The unmodified converter omits roots expired at time(). Reproduce the
        # dated published file at its recorded data date in this process only.
        wrapper = ('BEGIN { *CORE::GLOBAL::time = sub () { ' + str(epoch) +
                   ' }; } my $file = shift @ARGV; do $file; die $@ if $@;')
        result = subprocess.run(['perl', '-e', wrapper, str(tool), '-n', '-f', str(converted)], cwd=work,
                                capture_output=True)
        (destination / 'conversion.log').write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError('offline Mozilla CA conversion failed')
        if converted.read_bytes() != bundle.read_bytes():
            raise RuntimeError('dated CA bundle differs from its independently converted source bytes')
    for path in paths:
        shutil.copy2(path, destination / path.name)
    record = dict(identity=identity, identity_inputs=identity_inputs, certificates=len(expected),
        der_sha256=sorted(hashlib.sha256(value).hexdigest() for value in expected),
        conversion_offline=True, conversion_matches_published_bytes=True, publication_epoch=epoch,
        source_revision=dependency['source_revision'],
        products={path.name: digest(path) for path in destination.iterdir() if path.is_file()})
    manifest.write_text(json.dumps(record, indent=2) + '\n')
    print('CA_BUNDLE_PASS certificates=' + str(len(expected)) + ' identity=' + identity, flush=True)
    return destination


def runtime_files():
    destination = ensure()
    return {
        'etc/ssl/cert.pem': (0o100644, (destination / LOCK['ca_bundle']['archive']).read_bytes()),
        'usr/share/licenses/ca-bundle/MPL-2.0.txt': (0o100644, (destination / 'MPL-2.0.txt').read_bytes()),
        'usr/share/licenses/ca-bundle/source.json': (0o100644, (destination / 'manifest.json').read_bytes()),
    }


if __name__ == '__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    ensure()

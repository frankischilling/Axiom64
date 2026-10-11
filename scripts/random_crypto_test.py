#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run maintained cryptographic clients and independently verify their actual output."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
import tarfile

from build_musl import loader
from fetch import LOCK, ROOT
from random_administration_test import checked_run, fingerprint, snapshot
from random_crypto.inputs import products, provider
from random_crypto.peer import PAYLOAD, Peer, certificates
from random_crypto.wire import verify as verify_wire
from random_seed_test import image

NAMES = ('tls12', 'tls13', 'hostname', 'untrusted', 'expired', 'future')
ALGORITHMS = ('RSA', 'EC', 'ED25519')


def package(path):
    with tarfile.open(path, 'w', format=tarfile.USTAR_FORMAT) as archive:
        data = b'Axiom64 detached package signature acceptance\n'
        member = tarfile.TarInfo('package/NOTICE')
        member.mode, member.mtime, member.size = 0o644, 1700000000, len(data)
        archive.addfile(member, io.BytesIO(data))


def commands(openssl, busybox, ca, untrusted, signed_package, peers, dynamic, host):
    lines = ['umask 077', 'openssl() { ' + shlex.join(openssl) + ' "$@"; }',
             'busybox() { ' + shlex.quote(str(busybox)) + ' "$@"; }', 'openssl version -a',
             'openssl rand -out random.bin 32', 'test "$(busybox wc -c < random.bin)" -eq 32']
    for name in ALGORITHMS:
        options = ['-pkeyopt', 'rsa_keygen_bits:2048'] if name == 'RSA' else (
                  ['-pkeyopt', 'ec_paramgen_curve:prime256v1'] if name == 'EC' else [])
        lines += ['openssl genpkey -algorithm ' + name + ' ' + shlex.join(options) + ' -out ' + name + '.key',
                  f'openssl pkey -in {name}.key -check -noout',
                  f'openssl pkey -in {name}.key -pubout -outform DER -out {name}.der',
                  f'openssl pkey -in {name}.key -pubout -out {name}.pem']
        if name == 'ED25519':
            signer = f'openssl pkeyutl -sign -rawin -inkey {name}.key -in '
            verifier = f'openssl pkeyutl -verify -rawin -pubin -inkey {name}.pem -sigfile {name}.sig -in '
        else:
            signer = f'openssl dgst -sha256 -sign {name}.key -out {name}.sig '
            verifier = f'openssl dgst -sha256 -verify {name}.pem -signature {name}.sig '
        lines += [signer + shlex.quote(str(signed_package)) + (f' -out {name}.sig' if name == 'ED25519' else ''),
                  verifier + shlex.quote(str(signed_package)),
                  'busybox cp ' + shlex.quote(str(signed_package)) + ' damaged.tar',
                  "printf 'tampered\\n' >> damaged.tar",
                  f'if {verifier}damaged.tar; then echo CRYPTO_FAIL tampered_signature; exit 1; fi',
                  f"printf 'CRYPTO_PUBLIC {name} %s\\n' \"$(openssl base64 -A -in {name}.der)\"",
                  f"printf 'CRYPTO_SIGNATURE {name} %s\\n' \"$(openssl base64 -A -in {name}.sig)\"",
                  f'echo CRYPTO_SIGNATURE_PASS {name}']
    if dynamic:
        lines += ['openssl list -providers -provider default -provider legacy',
                  'openssl dgst -md4 -provider default -provider legacy ' + shlex.quote(str(signed_package)),
                  'echo CRYPTO_MODULE_PASS default_legacy']
    for peer in peers:
        trusted = untrusted if peer.name == 'untrusted' else ca
        hostname = 'wrong.test' if peer.name == 'hostname' else 'axiom64.test'
        command = shlex.join(['s_client', '-connect', host+':'+str(peer.port),
                             '-tls1_2' if peer.name == 'tls12' else '-tls1_3',
                             '-CAfile', str(trusted), '-verify_return_error', '-verify_hostname', hostname,
                             '-servername', 'axiom64.test', '-quiet'])
        if peer.expected:
            lines += ["printf '"+PAYLOAD.decode().replace('\n', '\\n')+"' | openssl " + command,
                      'echo CRYPTO_TLS_PASS ' + peer.name]
        else:
            lines += ['if openssl ' + command + ' < /dev/null; then echo CRYPTO_FAIL accepted_' +
                      peer.name + '; exit 1; fi', 'echo CRYPTO_TLS_REJECT ' + peer.name]
    lines.append('echo CRYPTO_CLIENT_PASS')
    return '\n'.join(lines)+'\n'


def exported(directory, text, openssl, signed_package):
    rows = []
    for name in ALGORITHMS:
        paths = {}
        for label, suffix in (('PUBLIC', 'der'), ('SIGNATURE', 'sig')):
            matches = re.findall('^CRYPTO_'+label+' '+name+r' ([A-Za-z0-9+/=]+)$', text, re.MULTILINE)
            if len(matches) != 1 or len(matches[0]) > 16384:
                raise RuntimeError('missing or repeated cryptographic export: '+name+' '+label)
            data = base64.b64decode(matches[0], validate=True)
            if not data:
                raise RuntimeError('empty cryptographic export')
            paths[suffix] = directory / (name+'.'+suffix)
            paths[suffix].write_bytes(data)
        public = directory / (name+'.pem')
        log = directory / (name+'-independent.log')
        with log.open('wb') as stream:
            subprocess.run([str(openssl), 'pkey', '-pubin', '-inform', 'DER', '-in', str(paths['der']),
                            '-out', str(public)], check=True, stdout=stream, stderr=subprocess.STDOUT)
            inspect = subprocess.run([str(openssl), 'pkey', '-pubin', '-in', str(public), '-text', '-noout'],
                                     check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stream.write(inspect.stdout)
            expected = {'RSA': b'(2048 bit)', 'EC': b'prime256v1', 'ED25519': b'ED25519 Public-Key'}[name]
            if expected not in inspect.stdout:
                raise RuntimeError('the exported public key has the wrong algorithm or strength')
            command = [str(openssl), 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(public),
                       '-sigfile', str(paths['sig']), '-in'] if name == 'ED25519' else [str(openssl),
                       'dgst', '-sha256', '-verify', str(public), '-signature', str(paths['sig'])]
            result = subprocess.run(command+[str(signed_package)], stdout=stream, stderr=subprocess.STDOUT)
            tampered = directory / 'tampered-package.tar'
            tampered.write_bytes(signed_package.read_bytes()+b'tampered\n')
            bad = subprocess.run(command+[str(tampered)], stdout=stream, stderr=subprocess.STDOUT)
        if result.returncode != 0 or bad.returncode == 0:
            raise RuntimeError('independent native signature or tamper verification failed: '+name)
        rows.append(dict(algorithm=name, public=fingerprint(paths['der']), signature=fingerprint(paths['sig']),
                         verified_returncode=result.returncode, tampered_returncode=bad.returncode,
                         log=fingerprint(log), passed=True))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--provider', choices=('build', 'runtime', 'native', 'all'), default='all')
    parser.add_argument('--linkage', choices=('static', 'dynamic', 'both'), default='both')
    parser.add_argument('--firmware', choices=('bios', 'uefi', 'both'), default='both')
    parser.add_argument('--transport', choices=('modern', 'legacy', 'both'), default='both')
    parser.add_argument('--timeout', type=float, default=180)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/random-crypto-results')
    args = parser.parse_args()
    if args.provider == 'native' and not args.native:
        parser.error('native glibc products run only with --native')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    profiles = ('build', 'runtime', 'native') if args.native and args.provider == 'all' else (
               ('build', 'runtime') if args.provider == 'all' else (args.provider,))
    providers = {name: provider(name) for name in profiles}
    observer = providers['build'][0] if 'build' in providers else next(iter(providers.values()))[0]
    observer = observer / 'static/stage/usr/bin/openssl'
    shutil.copyfile(observer, out / 'observer-openssl')
    observer = out / 'observer-openssl'
    certs = out / 'certificates'
    certificates(certs, observer)
    signed_package = out / 'package.tar'
    package(signed_package)
    subprocess.run(['make', '-s', '-j2', 'build/axiom64.elf', 'build/init', 'busybox',
                    *(f'build/{name}-{linkage}' for linkage in ('static', 'dynamic') for name in
                      ('random', 'random-seed', 'random-seed-probe'))], cwd=ROOT, check=True)
    inputs = snapshot(out)
    for path in [ROOT / 'scripts/random_crypto_test.py', ROOT / 'scripts/random_seed_test.py',
                 ROOT / 'scripts/image.py', *(ROOT / 'scripts/random_crypto').glob('*.py')]:
        inputs[str(path.relative_to(ROOT))] = fingerprint(path)
    (out / 'source-inputs.json').write_text(json.dumps(inputs, indent=2)+'\n')
    for name, (directory, _) in providers.items():
        shutil.copyfile(directory / 'manifest.json', out / ('openssl-'+name+'-manifest.json'))
    results = []
    busybox = ROOT / 'build' / ('busybox-'+LOCK['busybox']['version']) / 'busybox'
    linkages = ('static', 'dynamic') if args.linkage == 'both' else (args.linkage,)
    scenarios = [(name, linkage, 'native', 'native') for name in profiles for linkage in linkages] if args.native else [
        (('build' if linkage == 'static' else 'runtime') if args.provider == 'all' else profiles[0],
         linkage, firmware, transport) for linkage in linkages for firmware in
        (('bios', 'uefi') if args.firmware == 'both' else (args.firmware,)) for transport in
        (('modern', 'legacy') if args.transport == 'both' else (args.transport,))]
    for name, linkage, firmware, transport in scenarios:
        case = out / '-'.join((name, linkage, firmware, transport))
        case.mkdir(mode=0o700)
        directory, manifest = providers[name]
        stage = directory / linkage / 'stage'
        peers = [Peer(label, certs, args.timeout) for label in NAMES]
        row = dict(provider=name, linkage=linkage, firmware=firmware, transport=transport, passed=False,
                   openssl_identity=manifest['identity'], client=fingerprint(stage / 'usr/bin/openssl'))
        try:
            if args.native:
                environment = dict(os.environ, OPENSSL_CONF=str(stage / 'etc/ssl/openssl.cnf'),
                                   OPENSSL_MODULES=str(stage / 'usr/lib/ossl-modules'),
                                   LD_LIBRARY_PATH=str(stage / 'usr/lib'))
                executable = [str(stage / 'usr/bin/openssl')]
                if linkage == 'dynamic' and name != 'native':
                    executable.insert(0, str(loader(name)))
                script = case / 'commands.sh'
                script.write_text('set -eu\ncd '+shlex.quote(str(case))+'\n'+commands(
                    executable, busybox, certs / 'ca.pem', certs / 'untrusted.pem', signed_package,
                    peers, linkage == 'dynamic', '127.0.0.1'))
                command = ['env', *(key+'='+environment[key] for key in
                           ('OPENSSL_CONF', 'OPENSSL_MODULES', 'LD_LIBRARY_PATH')), 'sh', str(script)]
                process, text = checked_run(command, case / 'native.log', args.timeout)
            else:
                extras = products(directory, linkage)
                extras.update({'etc/ssl/test-ca.pem': certs / 'ca.pem',
                               'etc/ssl/untrusted-ca.pem': certs / 'untrusted.pem',
                               'tmp/package.tar': signed_package})
                setup = ('cd /tmp\n/bin/busybox ip link set eth0 up\n'
                         '/bin/busybox ip addr add 10.23.1.2/24 dev eth0\n'
                         '/bin/busybox ip route add default via 10.23.1.1\n')
                setup += commands(['/usr/bin/openssl'], '/bin/busybox', '/etc/ssl/test-ca.pem',
                                  '/etc/ssl/untrusted-ca.pem', '/tmp/package.tar', peers,
                                  linkage == 'dynamic', '10.23.1.1')
                iso = image(case, linkage, 'crypto', command=setup, extra_products=extras)
                capture = case / 'wire.pcap'
                command = ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '512M',
                           '-nic', 'none', '-cdrom', str(iso), '-display', 'none', '-serial', 'stdio',
                           '-monitor', 'none', '-no-reboot', '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
                           '-netdev', 'user,id=net,net=10.23.1.0/24,host=10.23.1.1',
                           '-device', 'virtio-net-pci,netdev=net,' +
                           ('disable-legacy=on' if transport == 'modern' else 'disable-modern=on'),
                           '-object', 'filter-dump,id=capture,netdev=net,file='+str(capture)]
                if firmware == 'uefi':
                    variables = case / 'VARS.fd'
                    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', variables)
                    command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                                '-drive', 'if=pflash,format=raw,file='+str(variables)]
                    row['firmware_inputs'] = {path: fingerprint(Path('/usr/share/OVMF') / path)
                                             for path in ('OVMF_CODE_4M.fd', 'OVMF_VARS_4M.fd')}
                process, text = checked_run(command, case / 'guest.log', args.timeout)
                row.update(image=fingerprint(iso), capture=fingerprint(capture))
            row.update(process)
            for peer in peers:
                peer.thread.join(timeout=2)
            row['peers'] = [peer.result for peer in peers]
            if (row['returncode'] != (0 if args.native else 1) or row['timed_out'] or
                    text.count('CRYPTO_CLIENT_PASS\n') != 1 or 'CRYPTO_FAIL ' in text or
                    not all(peer.result['passed'] for peer in peers)):
                raise RuntimeError('a real cryptographic client or native TLS peer failed')
            if linkage == 'dynamic' and 'CRYPTO_MODULE_PASS default_legacy\n' not in text:
                raise RuntimeError('dynamic OpenSSL did not load both actual providers')
            for label in ('tls12', 'tls13'):
                if text.count('AXIOM64_TLS_PEER_PASS ' + label + '\n') != 1:
                    raise RuntimeError('the actual client did not receive the authenticated peer response')
            expected_errors = {'hostname': 62, 'untrusted': 20, 'expired': 10, 'future': 9}
            for label, number in expected_errors.items():
                if text.count('verify error:num=' + str(number) + ':') != 1:
                    raise RuntimeError('the actual certificate rejection reason differs: ' + label)
            row['certificate_errors'] = expected_errors
            row['signatures'] = exported(case, text, observer, signed_package)
            if not args.native:
                row['wire'] = verify_wire(capture, row['peers'])
            row['passed'] = True
        except BaseException as error:
            row['error'] = repr(error)
            raise
        finally:
            for peer in peers:
                peer.close()
            row['peers'] = [peer.result for peer in peers]
            (case / 'result.json').write_text(json.dumps(row, indent=2)+'\n')
            results.append(row)
            (out / 'results.json').write_text(json.dumps(results, indent=2)+'\n')
        print(json.dumps(dict(case=case.name, passed=True, elapsed_ns=row['elapsed_ns'])), flush=True)
    if inputs != {path: fingerprint(ROOT / path) for path in inputs}:
        raise RuntimeError('the cryptographic client source changed during testing')
    public_keys = [item['public']['sha256'] for row in results for item in row['signatures']]
    if len(set(public_keys)) != len(public_keys):
        raise RuntimeError('fresh independent key-generation clients repeated a public key')
    (out / 'peer-inputs.json').write_text(json.dumps(dict(openssl=ssl.OPENSSL_VERSION,
         observer=fingerprint(observer), package=fingerprint(signed_package)), indent=2)+'\n')


if __name__ == '__main__':
    main()

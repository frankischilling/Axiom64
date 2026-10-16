#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare BusyBox wget default trust, helper name checks and its unverified fallback."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

import argparse
from build_musl import loader as musl_loader
from build_openssl import ensure as openssl
from ca_bundle import ensure as ca_bundle
from fetch import LOCK,ROOT
from http_download.native import command as ordinary
from http_download.native_process import run
from http_download.normal_peer import certificate_fixture
from http_download.peer import Peer,PAYLOAD_SHA256
from http_download_test import snapshot
from random_administration_test import checked_run,fingerprint

root = ROOT
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path,default=ROOT / 'build/http-downloads/native-wget')
args = parser.parse_args()
if os.geteuid() != 0:
    parser.error('native wget trust fixtures require the root build session')
out = args.output.resolve()
out.mkdir(parents=True,exist_ok=False)
tls = openssl('runtime')
loader = musl_loader('runtime')
busybox = ROOT / ('build/busybox-'+LOCK['busybox']['version']+'/busybox')
public = ca_bundle() / LOCK['ca_bundle']['archive']
shutil.copyfile(tls / 'manifest.json',out / 'openssl-runtime-manifest.json')
shutil.copyfile(loader.parents[2] / 'manifest.json',out / 'musl-runtime-manifest.json')
certs = out / 'certificates'
certificate_fixture(certs,openssl('build') / 'static/stage/usr/bin/openssl')
source_inputs = snapshot(out)
host_names = ('/etc/hosts','/etc/resolv.conf','/etc/passwd','/etc/group','/etc/ssl/cert.pem')
host_fingerprint = lambda name: fingerprint(Path(name)) if Path(name).exists() else dict(absent=True)
host_inputs = {name:host_fingerprint(name) for name in host_names}
rows = []
for label, helper, trusted, hostname, code in (
        ('http',True,False,'axiom64.test',0),
        ('https-helper-trusted',True,True,'axiom64.test',0),
        ('https-helper-public-only',True,False,'axiom64.test',1),
        ('https-helper-missing-store',True,'missing','axiom64.test',1),
        ('https-helper-damaged-store',True,'damaged','axiom64.test',1),
        ('https-helper-wrong-name',True,True,'wrong.test',1),
        ('https-helper-wrong-IP-name',True,True,'127.0.0.1',1),
        ('https-fallback-public-only-wrong-name',False,False,'wrong.test',0)):
    case = out / label
    case.mkdir()
    peer = Peer('http' if label == 'http' else 'untrusted', certs, 30)
    if not helper:
        import ssl
        peer.context.minimum_version = peer.context.maximum_version = ssl.TLSVersion.TLSv1_2
        peer.context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')

    row = dict(label=label, expected_status=code, actual_helper=helper, trusted_fixture=trusted,
               hostname=hostname, passed=False)
    try:
        with tempfile.TemporaryDirectory(prefix='axiom64-http-client-') as temporary:
            work = Path(temporary)
            work.chmod(0o755)
            binary = work / 'bin'
            binary.mkdir(mode=0o755)
            no_helper = work / 'no-helper'
            no_helper.mkdir(mode=0o755)
            sources = {'busybox':busybox,'loader':loader,
                       'openssl-real':tls / 'dynamic/stage/usr/bin/openssl',
                       **{name:tls / 'dynamic/stage/usr/lib' / name for name in ('libssl.so.3','libcrypto.so.3')}}
            for name,path in sources.items():
                shutil.copyfile(path,binary / name)
                (binary / name).chmod(0o755)
                assert fingerprint(binary / name) == fingerprint(path)
            (binary / 'openssl').write_text('#!/bin/sh\nexec '+shlex.join(['/usr/bin/env',
                'LD_LIBRARY_PATH='+str(binary),str(binary / 'loader'),str(binary / 'openssl-real')])+' "$@"\n')
            (binary / 'openssl').chmod(0o755)
            output = work / 'output'
            output.mkdir(mode=0o700)
            os.chown(output,60011,60011)
            (work / 'ssl').mkdir(mode=0o755)
            trust = work / 'ssl/cert.pem'
            trust.write_bytes(public.read_bytes()+((certs / 'ca.pem').read_bytes() if trusted is True else b''))
            trust.chmod(0o644)
            if trusted == 'missing':
                trust.unlink()
            elif trusted == 'damaged':
                trust.write_bytes(b'damaged store\n')
            hosts = work / 'hosts'
            hosts.write_bytes(Path('/etc/hosts').read_bytes()+b'\n127.0.0.1 axiom64.test wrong.test\n')
            hosts.chmod(0o644)
            child = work / 'mount.py'
            child.write_text('''import os,subprocess,sys
for source,target in ((sys.argv[1],'/etc/ssl'),(sys.argv[2],'/etc/hosts')):
    subprocess.run(['mount','--bind',source,target],check=True)
os.umask(0o077)
os.execvp(sys.argv[3],sys.argv[3:])
''')
            scheme = 'http' if label == 'http' else 'https'
            argv = [sys.executable,str(child),str(trust.parent),str(hosts),'setpriv','--reuid','60011',
                    '--regid','60011','--clear-groups','env','-i',
                    'LC_ALL=C','PATH='+str(binary if helper else no_helper),str(binary / 'busybox'),
                    'wget','-q','-T','8','-O',str(output / 'download.bin'),
                    f'{scheme}://{hostname}:{peer.port}/fixed']
            process = run(ordinary(work,argv),case / 'native.log',None,20)
            text = (case / 'native.log').read_text()
            row.update(process=process, actual_inputs={name:fingerprint(path) for name,path in sources.items()},
                       namespace_trust=fingerprint(trust) if trust.exists() else dict(absent=True), namespace_hosts=fingerprint(hosts))
            assert not process['timed_out'] and process['returncode'] == code,(label,process,text)
            if code == 0:
                metadata = (output / 'download.bin').stat()
                assert (metadata.st_uid,metadata.st_gid,metadata.st_mode & 0o777) == (60011,60011,0o600)
                assert fingerprint(output / 'download.bin')['sha256'] == PAYLOAD_SHA256
                shutil.copyfile(output / 'download.bin',case / 'download.bin')
            if not helper:
                assert 'TLS certificate validation not implemented' in text
    except BaseException as error:
        row['error'] = repr(error)
        raise
    finally:
        try:
            peer.close()
        except BaseException as error:
            row['cleanup_error'] = repr(error)
            raise
        finally:
            row['peer'] = peer.result
            row['passed'] = not row.get('error') and not row.get('cleanup_error') and \
                not peer.result['errors'] and peer.result['closed'] and \
                len(peer.result['requests']) == int(code == 0) and \
                len(peer.result['rejected_handshakes'])+len(peer.result['rejected_after_handshake']) == \
                int(code != 0 and label != 'https-helper-wrong-IP-name')
            rows.append(row)
            (out / 'results.json').write_text(json.dumps(rows,indent=2)+'\n')
    assert not peer.result['errors'] and peer.result['closed']
    assert row['passed'],row
    assert len(peer.result['requests']) == int(code == 0)
    rejects = len(peer.result['rejected_handshakes'])+len(peer.result['rejected_after_handshake'])
    assert rejects == int(code != 0 and label != 'https-helper-wrong-IP-name')
assert all(host_fingerprint(name) == value for name,value in host_inputs.items())
assert source_inputs == {name:fingerprint(ROOT / name) for name in source_inputs}
(out / 'receipt.json').write_text(json.dumps(dict(passed=True,cases=len(rows),host_files_unchanged=True,
    host_inputs=host_inputs,actual_ordinary_uid=60011,actual_source_built_busybox_sha256=fingerprint(busybox)['sha256'],
    actual_source_built_openssl_helper=True,default_trust_path=True,
    helper_checks_issuer_and_name=True,numeric_IP_helper_exits_before_TLS=True,
    missing_and_damaged_default_stores_rejected=True,all_actual_TLS_rejections_verified=True,fallback_accepts_untrusted_and_wrong_name=True,
    fallback_prints_validation_not_implemented=True,guest_acceptance=False),indent=2)+'\n')
print('NATIVE_WGET_ACTUAL_CONTRACT_PASS helper_verifies=true fallback_verifies=false')

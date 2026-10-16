#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare actual ordinary-user download failures in an owned Linux network namespace."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

import argparse
from build_curl import ensure as curl_provider
from build_musl import loader as musl_loader
from build_openssl import ensure as tls_provider
from fetch import ROOT
from dns_peer import question,response
from http_download.audit import fingerprint
from http_download.native import command as ordinary
from http_download.native_process import run
from http_download.peer import Peer,PAYLOAD_SHA256
from http_download_test import snapshot

root = ROOT
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path,default=ROOT / 'build/http-downloads/normal-native')
parser.add_argument('--child',action='store_true',help=argparse.SUPPRESS)
args = parser.parse_args()
out = args.output.resolve()
if os.geteuid() != 0:
    parser.error('isolated native download comparisons require the root build session')
if not args.child:
    out.mkdir(parents=True,exist_ok=False)
    configuration = {}
    for name in ('build','runtime','native'):
        curl = curl_provider(name)
        tls = tls_provider(name)
        configuration[name] = dict(curl=str(curl),tls=str(tls),
            loader=str(musl_loader(name)) if name != 'native' else None)
        for package,path in (('curl',curl / 'manifest.json'),('openssl',tls / 'manifest.json')):
            shutil.copyfile(path,out / (package+'-'+name+'-manifest.json'))
    configuration['_parent_namespaces'] = {name:os.readlink('/proc/self/ns/'+name) for name in ('net','mnt')}
    (out / 'providers.json').write_text(json.dumps(configuration,indent=2)+'\n')
    source_inputs = snapshot(out)
    host = {name:fingerprint(Path(name)) for name in ('/etc/resolv.conf','/etc/passwd','/etc/group')}
    network = subprocess.check_output(['ip','-json','address','show'])
    argv = ['unshare','--net','--mount','--propagation','private','--',sys.executable,__file__,'--output',str(out),'--child']
    try:
        process = run(argv,out / 'namespace.log',None,120)
        (out / 'namespace-process.json').write_text(json.dumps(process,indent=2)+'\n')
        assert not process['timed_out'] and process['returncode'] == 0,process
    finally:
        assert host == {name:fingerprint(Path(name)) for name in host}
        assert network == subprocess.check_output(['ip','-json','address','show'])
    assert source_inputs == {name:fingerprint(ROOT / name) for name in source_inputs}
    receipt = dict(passed=True,profiles=6,cases=30,source_inputs_unchanged=True,host_files_and_interfaces_unchanged=True,
        namespace_command=argv,host_inputs=host,guest_acceptance=False)
    (out / 'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('NATIVE_DOWNLOAD_FAILURES_PASS profiles=6 cases=30 host_unchanged=true')
    sys.exit(0)

configuration = json.loads((out / 'providers.json').read_text())
if os.getpid() != 1 or any(os.readlink('/proc/self/ns/'+name) == value
                         for name,value in configuration['_parent_namespaces'].items()):
    raise RuntimeError('native child requires its owned PID, network and mount namespaces')
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','link','add','axiom64-fixture','type','dummy'],check=True)
subprocess.run(['ip','addr','add','10.23.1.1/24','dev','axiom64-fixture'],check=True)
subprocess.run(['ip','link','set','axiom64-fixture','up'],check=True)
(out / 'owned-addresses.json').write_bytes(subprocess.check_output(['ip','-json','address','show']))
resolver = out / 'namespace-resolv.conf'
resolver.write_text('nameserver 127.0.0.55\noptions timeout:1 attempts:1\n')
resolver.chmod(0o644)
subprocess.run(['mount','--bind',str(resolver),'/etc/resolv.conf'],check=True)
stop = threading.Event()
dns = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
dns.bind(('127.0.0.55',53))
dns.settimeout(.1)
queries,errors = [],[]
def answer():
    while not stop.is_set():
        try:
            raw,address = dns.recvfrom(4096)
        except socket.timeout:
            continue
        try:
            name = question(raw)
            assert name in ('lane0.axiom64.test','missing.axiom64.test')
            reply = response(raw,((127,0,0,1),)) if name.startswith('lane0') else response(raw,rcode=3)
            queries.append(dict(name=name,query=raw.hex(),answer=reply.hex()))
            dns.sendto(reply,address)
        except BaseException as error:
            errors.append(repr(error))
thread = threading.Thread(target=answer)
thread.start()
rows = []
certificates = out
configuration = json.loads((out / 'providers.json').read_text())
try:
    for provider in ('build','runtime','native'):
        curl,tls = (Path(configuration[provider][name]) for name in ('curl','tls'))
        for package,path in (('curl',curl / 'manifest.json'),('openssl',tls / 'manifest.json')):
            assert fingerprint(path) == fingerprint(out / (package+'-'+provider+'-manifest.json'))
        for linkage in ('static','dynamic'):
            case = out / (provider+'-'+linkage)
            case.mkdir()
            peer = Peer('http',certificates,30)
            reserved = socket.socket()
            reserved.bind(('127.0.0.1',0))
            refused = reserved.getsockname()[1]
            try:
                with tempfile.TemporaryDirectory(prefix='axiom64-http-client-') as temporary:
                    work = Path(temporary)
                    work.chmod(0o755)
                    binary = work / 'bin'
                    binary.mkdir(mode=0o755)
                    binary.chmod(0o755)
                    inputs = {'curl':curl / linkage / 'stage/usr/bin/curl'}
                    if linkage == 'dynamic':
                        inputs.update({'libcurl.so.4':curl / 'dynamic/stage/usr/lib/libcurl.so.4',
                            **{name:tls / 'dynamic/stage/usr/lib' / name for name in ('libssl.so.3','libcrypto.so.3')}})
                        if provider != 'native':
                            loader = Path(configuration[provider]['loader'])
                            inputs.update({name:loader for name in ('loader','libc.so','libc.musl-x86_64.so.1')})
                    for name,path in inputs.items():
                        shutil.copyfile(path,binary / name)
                        (binary / name).chmod(0o755)
                        assert fingerprint(path) == fingerprint(binary / name)
                    output = work / 'output'
                    output.mkdir(mode=0o700)
                    os.chown(output,60011,60011)
                    deny = output / 'deny'
                    deny.mkdir(mode=0o500)
                    client = [str(binary / 'curl')]
                    if linkage == 'dynamic' and provider != 'native':
                        client.insert(0,str(binary / 'loader'))
                    account_prefix = ordinary(work,['/bin/true'])[:-1]
                    for label,code,url,target in (
                        ('http',0,f'http://lane0.axiom64.test:{peer.port}/fixed',output / 'download.bin'),
                        ('nxdomain',6,f'http://missing.axiom64.test:{peer.port}/fixed',output / 'missing.bin'),
                        ('refused',7,f'http://lane0.axiom64.test:{refused}/fixed',output / 'refused.bin'),
                        ('unreachable',28,'http://10.23.1.254:80/fixed',output / 'unreachable.bin'),
                        ('permission',23,f'http://lane0.axiom64.test:{peer.port}/small',deny / 'output.bin')):
                        argv = [*account_prefix,'setpriv','--reuid','60011','--regid','60011','--clear-groups',
                            'env','-i','HOME='+str(output),'LC_ALL=C','LD_LIBRARY_PATH='+str(binary),
                            *client,'--ipv4','--noproxy','*','--connect-timeout','2','--max-time','2',
                            '--silent','--show-error','--fail','--output',str(target),url]
                        process = run(argv,case / (label+'.stdout'),case / (label+'.stderr'),10)
                        elapsed = process['elapsed_ns']/1_000_000_000
                        stderr = (case / (label+'.stderr')).read_bytes()
                        row = dict(provider=provider,linkage=linkage,label=label,expected=code,
                            status=process['returncode'],elapsed_seconds=elapsed,process=process,
                            products={name:fingerprint(path) for name,path in inputs.items()},passed=False)
                        rows.append(row)
                        (out / 'results.json').write_text(json.dumps(rows,indent=2)+'\n')
                        assert not process['timed_out'] and process['returncode'] == code,(provider,linkage,label,process,stderr)
                        assert code == 0 or ('curl: ('+str(code)+')').encode() in stderr
                        if label == 'unreachable':
                            assert 1.95 <= elapsed <= 5
                        if code == 0:
                            info = target.stat()
                            assert fingerprint(target)['sha256'] == PAYLOAD_SHA256
                            assert (info.st_uid,info.st_gid,info.st_mode & 0o777) == (60011,60011,0o600)
                            shutil.copyfile(target,case / 'download.bin')
                        row['passed'] = True
                        (out / 'results.json').write_text(json.dumps(rows,indent=2)+'\n')
            finally:
                reserved.close()
                try:
                    peer.close()
                finally:
                    (case / 'peer.json').write_text(json.dumps(peer.result,indent=2)+'\n')
            assert not peer.result['errors'] and len(peer.result['requests']) == 2
    assert not errors and {row['name'] for row in queries} == {'lane0.axiom64.test','missing.axiom64.test'}
finally:
    stop.set()
    thread.join(timeout=2)
    dns.close()
    (out / 'dns.json').write_text(json.dumps(dict(queries=queries,errors=errors),indent=2)+'\n')

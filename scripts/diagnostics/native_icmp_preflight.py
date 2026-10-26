# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise unchanged original IPv4 clients through the production native peer."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import ipv4_fragment_native as tested


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def interrupted(number, frame):
    raise InterruptedError(f'IPv4 diagnostic interrupted by signal {number}')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--child',choices=('native','static','dynamic'))
    args=parser.parse_args()
    assert platform.release()=='6.17.0-1022-azure' and os.geteuid()==0
    output=ROOT/'build/native-icmp-preflight-diagnostic'
    if args.child:
        original=output/'originals'/args.child
        receipt=json.loads((original/'original.json').read_text())
        command=[str(original/item['name']) for item in receipt['products']]+['--fragments']
        assert all(digest(original/item['name'])==item['sha256'] for item in receipt['products'])
        # This diagnostic changes only the location of preserved products. The
        # production peer, clock reader and all real protocol windows execute.
        tested.client=lambda profile,pmtu_only=False,lifetime_only=False:command
        passed=tested.child(args.child,output/args.child)
        assert all(digest(original/item['name'])==item['sha256'] for item in receipt['products'])
        return 0 if passed else 1
    output.mkdir(parents=True,exist_ok=False)
    for profile in ('native','static','dynamic'):
        source=args.reference/profile
        before=json.loads((source/'preexecution.json').read_text())
        assert before['kernel']['release']==platform.release()
        assert before['requested_fragment_timeout_seconds']==60 and before['requested_path_mtu_lifetime_seconds']==600
        for name,wanted in before['source_sha256'].items():
            if name.startswith('userspace/'):
                assert digest(ROOT/name)==wanted,name
        original=output/'originals'/profile
        original.mkdir(parents=True)
        products=[]
        for index,name in enumerate(before['command'][:-1]):
            filename=f'{index}-{Path(name).name}'
            shutil.copy2(source/'products'/filename,original/filename)
            (original/filename).chmod(0o755)
            assert digest(original/filename)==before['executable_sha256'][name]
            products.append(dict(name=filename,sha256=digest(original/filename)))
        (original/'original.json').write_text(json.dumps(dict(profile=profile,products=products,
            original_preexecution=before),indent=2)+'\n')
    processes=[]
    def compare(profile):
        command=['unshare','--net',sys.executable,__file__,'--reference',str(args.reference),'--child',profile]
        with (output/f'{profile}.log').open('xb') as log:
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            processes.append(process)
            status=process.wait(timeout=840)
        receipt=json.loads((output/profile/'receipt.json').read_text())
        return dict(profile=profile,wrapper_exit=status,passed=status==0 and receipt['passed'],
                    native_icmp_preflight=receipt['native_icmp_preflight_capture_audit'])
    handlers={number:signal.signal(number,interrupted) for number in (signal.SIGTERM,signal.SIGINT)}
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            results=list(pool.map(compare,('native','static','dynamic')))
    finally:
        for number,handler in handlers.items():
            signal.signal(number,handler)
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL)
                    process.wait()
    proof=dict(diagnostic_only=True,feature_acceptance=False,profiles=results,
        actual_production_peer_passed=all(row['passed'] for row in results),
        original_C_products_unchanged=True,fragment_timeout_seconds=60,path_mtu_lifetime_seconds=600)
    (output/'diagnostic.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof),flush=True)
    assert len(results)==3 and proof['actual_production_peer_passed']
    return 0


if __name__=='__main__':
    raise SystemExit(main())

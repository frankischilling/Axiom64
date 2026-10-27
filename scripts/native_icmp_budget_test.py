# SPDX-License-Identifier: GPL-3.0-or-later
"""Retain cold native ICMP controls beside acknowledged-error comparisons."""
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import zipfile
from fetch import ROOT


def require(value, reason):
    if not value:
        raise ValueError('native ICMP budget: '+reason)


def checksum(data):
    value=sum(int.from_bytes(data[at:at+2],'big') for at in range(0,len(data),2))
    while value>>16:
        value=(value&65535)+(value>>16)
    return value^65535


def packet(record, lane, *, primer=False):
    frame,reply=bytes.fromhex(record['input']),bytes.fromhex(record['reply'])
    require(len(frame)==60 and frame[:12]==bytes([0x52,0x54,0,0x12,0x34,16+lane,2,0x41,0x58,0x49,0x50,lane]) and
            frame[12:15]==b'\x08\0\x45', 'original input Ethernet ownership')
    ip=frame[14:42]
    require(ip[:4]==b'\x45\0\0\x1c' and ip[6:10]==b'\0\0\x40\x11' and not checksum(ip[:20]) and
            int.from_bytes(ip[4:6],'big')==(0x7b00 if primer else 0x7c00+lane) and
            ip[12:20]==bytes([10,202,lane+1,1,10,202,lane+1,2]), 'original UDP input bytes and checksum')
    ports=(61398,61399) if primer else (44000+lane,44100)
    require(ip[20:]==ports[0].to_bytes(2,'big')+ports[1].to_bytes(2,'big')+b'\0\x08\0\0',
            'exact owned closed-port tuple')
    require(0<record['write_before_ns']<=record['write_after_ns'], 'actual input syscall clock bracket')
    if reply:
        require(len(reply)==70 and reply[:12]==frame[6:12]+frame[:6] and reply[12:16]==b'\x08\0\x45\xc0' and
                reply[16:18]==b'\0\x38' and reply[20:24]==b'\0\0\x40\x01' and
                reply[26:34]==ip[16:20]+ip[12:16] and reply[34:36]==b'\x03\x03' and
                not checksum(reply[14:34]) and not checksum(reply[34:]) and reply[38:42]==b'\0'*4 and
                reply[42:]==ip, 'actual complete error quote, tuple and checksums')
        require(record['read_ns']>=record['write_before_ns'], 'actual quote follows the input')
    else:
        require(record['read_ns']==0, 'suppressed input has no invented response clock')
    return bool(reply)


def audit(rows, trials=256):
    require(len(rows)==trials*3+2 and rows[0]['native_reference_control'] is True and
            rows[0]['guest_acceptance'] is False and rows[0]['fixed_trials_each']==trials,
            'complete fixed native cohort')
    cases=rows[1:-1]
    require({(row['trial'],row['mode']) for row in cases}=={(trial,mode) for trial in range(trials) for mode in range(3)},
            'all cold, staggered and primed profiles once')
    cpus=None
    suppressed=[0,0,0]
    quotes=0
    for row in cases:
        mode=row['mode']
        require(row['aligned']==(mode!=0) and row['primed']==(mode==2) and
                row['gap_ns']==(1000000 if mode==0 else 0) and row['out_errors']==0 and
                row['received']+row['rate_global']==2 and 0<=row['rate_global']<=1,
                'actual default native error decisions are fully accounted')
        if mode==0:
            require(row['lanes'][1]['write_before_ns']>=row['lanes'][0]['write_after_ns']+row['gap_ns'],
                    'staggered second input follows the completed first write by the original gap')
        assigned=[item['cpu'] for item in row['lanes']]
        if cpus is None:
            cpus=assigned
        require(len(assigned)==2 and assigned==cpus and 0<=cpus[0]<cpus[1], 'same two owned packet CPUs')
        found=sum(packet(item,lane) for lane,item in enumerate(row['lanes']))
        require(found==row['received'], 'decision counters match actual returned packet bytes')
        quotes+=found
        if mode==2:
            require(row['primer'] is not None and packet(row['primer'],0,primer=True) and
                    row['primer']['cpu']==cpus[0] and
                    row['primer']['read_ns']<min(item['write_before_ns'] for item in row['lanes']),
                    'actual owned preflight finishes before the unchanged simultaneous pair')
            quotes+=1
        else:
            require(row['primer'] is None, 'cold controls retain their original first-error condition')
        if mode!=1:
            require(row['rate_global']==0 and found==2, 'staggered and primed original pairs both emit errors')
        suppressed[mode]+=row['rate_global']>0
    final=rows[-1]
    require(final['passed'] is True and final['profiles']==trials*3 and final['guest_acceptance'] is False and
            [final[key] for key in ('staggered_suppressed_profiles','aligned_suppressed_profiles','primed_suppressed_profiles')]==suppressed,
            'final producer counters match every actual case')
    return dict(passed=True,native_reference_control=True,guest_acceptance=False,profiles=trials*3,
                actual_inputs=trials*7,actual_quotes=quotes,owned_cpus=cpus,
                staggered_suppressed_profiles=suppressed[0],cold_aligned_suppressed_profiles=suppressed[1],
                primed_suppressed_profiles=suppressed[2])


def controls(rows, path):
    at=next(n for n,row in enumerate(rows) if row.get('mode')==2)
    staggered=next(n for n,row in enumerate(rows) if row.get('mode')==0)
    def move_second(data,gap):
        pair=data[staggered]['lanes']
        shift=pair[0]['write_after_ns']+gap-pair[1]['write_before_ns']
        for name in ('write_before_ns','write_after_ns','read_ns'):
            if pair[1][name]:
                pair[1][name]+=shift
    mutations={
        'collapsed-stagger':lambda data:move_second(data,999999),
        'reversed-stagger':lambda data:move_second(data,-1),
        'missing-profile':lambda data:data.pop(1),
        'duplicate-profile':lambda data:data.__setitem__(1,copy.deepcopy(data[2])),
        'missing-primer':lambda data:data[at].__setitem__('primer',None),
        'primer-after-pair':lambda data:data[at]['primer'].__setitem__('read_ns',max(item['write_before_ns'] for item in data[at]['lanes'])+1),
        'wrong-primer-cpu':lambda data:data[at]['primer'].__setitem__('cpu',-1),
        'wrong-quote':lambda data:data[at]['lanes'][0].__setitem__('reply',data[at]['lanes'][0]['reply'][:-2]+'ff'),
        'wrong-primer-input':lambda data:data[at]['primer'].__setitem__('input','ff'+data[at]['primer']['input'][2:]),
        'unaccounted-error':lambda data:data[at].__setitem__('rate_global',1),
        'invented-read-time':lambda data:data[at]['lanes'][0].__setitem__('read_ns',1),
        'false-summary':lambda data:data[-1].__setitem__('primed_suppressed_profiles',1)}
    verdicts={}
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,change in mutations.items():
            data=copy.deepcopy(rows)
            change(data)
            member=name+'.json'
            archive.writestr(member,json.dumps(data))
            reopened=json.loads(archive.read(member))
            try:
                audit(reopened)
            except (ValueError,KeyError,TypeError) as error:
                verdicts[name]=str(error)
            else:
                raise ValueError('native ICMP budget damaged control passed: '+name)
    require(len(verdicts)==12, 'all serialized damaged controls reopened and rejected')
    return verdicts


def interrupted(number, frame):
    raise InterruptedError(f'native ICMP control interrupted by signal {number}')


def main():
    directory=ROOT/'build/native-icmp-budget-evidence'
    directory.mkdir(parents=True,exist_ok=False)
    binary=ROOT/'build/native-icmp-budget'
    sources=['scripts/tests/native_icmp_budget.c','scripts/native_icmp_budget_test.py','Makefile']
    manifest=dict(kernel=platform.uname()._asdict(),command=[str(binary),'256'],
        source_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources},
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (directory/'preexecution.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (directory/'client').write_bytes(binary.read_bytes())
    (directory/'sources').mkdir()
    for name in sources:
        (directory/'sources'/Path(name).name).write_bytes((ROOT/name).read_bytes())
    process=None
    handlers={number:signal.signal(number,interrupted) for number in (signal.SIGTERM,signal.SIGINT)}
    try:
        with (directory/'results.jsonl').open('xb') as output, (directory/'client.log').open('xb') as errors:
            process=subprocess.Popen(manifest['command'],stdout=output,stderr=errors,start_new_session=True)
            status=process.wait(timeout=150)
    finally:
        for number,handler in handlers.items():
            signal.signal(number,handler)
        if process is not None and process.poll() is None:
            os.killpg(process.pid,signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL)
                process.wait()
    require(status==0, 'all actual native controls complete; original failure logs retained')
    rows=[json.loads(line) for line in (directory/'results.jsonl').read_text().splitlines()]
    result=audit(rows)
    require(rows[0]['kernel']==manifest['kernel']['release'] and
            hashlib.sha256(binary.read_bytes()).hexdigest()==manifest['binary_sha256'] and
            all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==manifest['source_sha256'][name] for name in sources),
            'original running kernel and unchanged source/products')
    result['damaged_controls']=controls(rows,directory/'damaged-controls.zip')
    (directory/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)


if __name__=='__main__':
    main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare complete original native/guest per-message IPv6 control observations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

SCALARS = {'case','raw','named','variant','sticky','sticky_errno','result','errno',
           'received','receive_errno','length','flags','hops','class'}
BUFFERS = {'control','payload'}
DONE = 'IPV6_SEND_CONTROLS_DONE cases=480 transports=2 destinations=2 variants=120'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(text):
    indices = [int(match.group(1)) for line in text.splitlines() if
               (match := re.fullmatch(r'IPV6_SEND_CONTROLS_INTERFACE loopback=(\d+)',line))]
    require(len(indices)==1 and 0<indices[0]<2**32,'one actual loopback interface')
    rows=[]
    for line in text.splitlines():
        if not line.startswith('IPV6_SEND_CONTROLS case='):
            continue
        pairs=[item.split('=',1) for item in line.split()[1:]]
        require(all(len(pair)==2 for pair in pairs),'complete send-control fields')
        row=dict(pairs)
        require(len(pairs)==len(SCALARS|BUFFERS) and set(row)==SCALARS|BUFFERS,
                'exact send-control field inventory')
        require(all(re.fullmatch(r'-?\d+',row[key]) for key in SCALARS),'integer original observations')
        at=len(rows)
        require((int(row['case']),int(row['raw']),int(row['named']),int(row['variant']))==
                (at,at//240,at%240//120,at%120),'complete ordered transport/destination variants')
        for key,size in [('control',192),('payload',32)]:
            require(re.fullmatch('[0-9a-f]*',row[key]) is not None and len(row[key])==size*2,
                    'complete visible original '+key)
        if int(row['received'])>=0:
            data=bytearray.fromhex(row['control'])
            require(data[:16]==bytes.fromhex('24000000000000002900000032000000') and
                    data[16:32]==bytes(15)+b'\1' and
                    int.from_bytes(data[32:36],'little')==indices[0],
                    'actual received loopback packet-info identity')
            # Translate only the validated actual loopback index. Every payload,
            # padding byte, traffic-class bit and syscall result remains exact.
            data[32:36]=(1).to_bytes(4,'little')
            row['control']=data.hex()
        rows.append(row)
    require(len(rows)==480 and text.splitlines().count(DONE)==1 and
            'IPV6_SEND_CONTROLS_FAIL' not in text,'complete actual send-control execution')
    return rows


def differences(expected,text):
    return [dict(case=at,fields=sorted(key for key in actual if wanted[key]!=actual[key]))
            for at,(wanted,actual) in enumerate(zip(expected,parse(text))) if wanted!=actual]


def damage(text,name):
    lines=text.splitlines()
    at=next(i for i,line in enumerate(lines) if line.startswith('IPV6_SEND_CONTROLS case=4 '))
    if name=='missing-case':
        del lines[at]
    elif name=='duplicate-case':
        lines.insert(at,lines[at])
    else:
        if name=='wrong-fault-order':
            at=next(i for i,line in enumerate(lines) if line.startswith('IPV6_SEND_CONTROLS case=73 '))
        row=dict(item.split('=',1) for item in lines[at].split()[1:])
        scalar={'wrong-result':'result','wrong-errno':'errno','wrong-receive':'received',
                'wrong-fault-order':'errno','changed-sticky':'class','wrong-length':'length',
                'wrong-flags':'flags','wrong-hop-option':'hops'}
        if name in scalar:
            key=scalar[name];row[key]=str(int(row[key])^1)
        else:
            key,offset={'wrong-address':('control',31),'wrong-index':('control',32),
                'wrong-hop-control':('control',56),'wrong-class-control':('control',80),
                'written-padding':('control',37),'wrong-payload':('payload',10)}[name]
            data=bytearray.fromhex(row[key]);data[offset]^=1;row[key]=data.hex()
        lines[at]='IPV6_SEND_CONTROLS '+' '.join(key+'='+value for key,value in row.items())
    return '\n'.join(lines)+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',type=Path,action='append',required=True)
    parser.add_argument('--guest',type=Path,action='append',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--damaged',type=Path,required=True)
    args=parser.parse_args()
    paths=[*args.native,*args.guest]
    require(len(set(paths))==len(paths),'distinct original logs')
    originals={str(path):path.read_bytes() for path in paths}
    native=[parse(originals[str(path)].decode()) for path in args.native]
    require(len(native)==3 and all(rows==native[0] for rows in native),'three agreeing actual native linkages')
    results=[dict(path=str(path),differences=differences(native[0],originals[str(path)].decode()))
             for path in args.guest]
    names=('missing-case','duplicate-case','wrong-result','wrong-errno','wrong-receive',
           'wrong-fault-order','changed-sticky','wrong-length','wrong-flags','wrong-hop-option',
           'wrong-address','wrong-index','wrong-hop-control','wrong-class-control',
           'written-padding','wrong-payload')
    rejected=[]
    if all(not row['differences'] for row in results):
        with zipfile.ZipFile(args.damaged,'w',zipfile.ZIP_DEFLATED) as archive:
            for profile,path in enumerate(args.guest):
                for name in names:
                    altered=damage(originals[str(path)].decode(),name)
                    archive.writestr(f'{profile}-{name}.log',altered)
                    try:
                        changed=differences(native[0],altered)
                    except ValueError:
                        changed=True
                    require(changed,'damaged send-control evidence rejected: '+name)
                    rejected.append(dict(profile=profile,name=name))
            archive.writestr('rejections.json',json.dumps(rejected,indent=2))
    require(all(path.read_bytes()==originals[str(path)] for path in paths),'original logs unchanged')
    result=dict(passed=all(not row['differences'] for row in results),cases_each=480,
                native_profiles=3,guest_profiles=len(results),profiles=results,
                damaged_rejected=len(rejected),full_F12_complete=False,
                original_sha256={name:hashlib.sha256(data).hexdigest() for name,data in originals.items()})
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('profiles','original_sha256')}),
          'differences_each='+str([len(row['differences']) for row in results]))
    return 0 if result['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())

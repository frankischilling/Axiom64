# SPDX-License-Identifier: GPL-3.0-or-later
"""Run complete native/linkage/firmware/device output and retained-send comparisons."""
import argparse
import json
from pathlib import Path
import os
import shutil
import subprocess
import sys
from fetch import ROOT
from ipv4_native_capture_controls import damaged as cpu_damaged
from ipv4_receive_wire_contract import protected
from ipv4_receive_wire_records import require
from ipv4_send_wire_contract import verify,cohort
from ipv4_send_wire_controls import damaged,native_damaged


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,default=ROOT/'build/ipv4-send-wire')
    args=parser.parse_args()
    directory=(ROOT/args.directory).resolve()
    require(directory.is_relative_to((ROOT/'build').resolve()),'designated ignored output')
    directory.mkdir(parents=True,exist_ok=False)
    kernel=ROOT/'build/axiom64.elf'
    if kernel.exists() and kernel.stat().st_nlink>1:
        from tcp6.inputs import digest
        temporary=kernel.with_name('axiom64-send-wire-detached.elf')
        require(not temporary.exists(),'unused kernel detach path')
        shutil.copy2(kernel,temporary)
        require(digest(temporary)==digest(kernel) and temporary.stat().st_nlink==1,'verified independent kernel copy')
        os.replace(temporary,kernel)
    command=['make','-j4','build/axiom64.elf','build/init','busybox',
        *('build/ipv4-send-wire-'+profile for profile in ('native','static','dynamic'))]
    with (directory/'build.log').open('xb') as output:
        subprocess.run(command,cwd=ROOT,stdout=output,stderr=subprocess.STDOUT,check=True)
    cases=[('linux-'+profile,['--native','--profile',profile]) for profile in ('native','static','dynamic')]
    cases += [(profile+'-'+firmware+'-'+transport,['--profile',profile,'--firmware',firmware,'--transport',transport])
        for profile in ('static','dynamic') for firmware in ('bios','uefi') for transport in ('modern','legacy')]
    values,paths=[],[]
    for name,arguments in cases:
        case=directory/name
        with (directory/(name+'.log')).open('xb') as output:
            process=subprocess.Popen([sys.executable,'-B',str(ROOT/'scripts/ipv4_send_wire_test.py'),
                *arguments,'--directory',str(case)],cwd=ROOT,stdout=output,stderr=subprocess.STDOUT)
            (directory/'process.json').write_text(json.dumps(dict(pid=process.pid,case=name,status='running')))
            try:
                result=process.wait()
            except BaseException:
                process.kill();process.wait()
                raise
            (directory/'process.json').write_text(json.dumps(dict(pid=process.pid,case=name,status='completed',returncode=result)))
        require(result==0,'actual native/guest physical send producer: '+name)
        values.append(verify(case));paths.append(case)
        print('IPV4_SEND_WIRE_PROFILE_PASS '+name,flush=True)
    checked=cohort(values)
    before=protected(paths)
    checked['reopened_controls_rejected']=damaged(directory/'static-bios-modern',directory/'damaged-controls.zip')
    checked['native_peer_controls_rejected']=native_damaged(directory/'linux-native',directory/'native-damaged-controls.zip')
    checked['native_cpu_controls_rejected']=cpu_damaged(directory/'linux-native',directory/'native-cpu-controls.zip',verify)
    require(protected(paths)==before,'all original runtime bytes, sizes, owners and modes preserved')
    checked['protected_inputs']=before
    checked['source']=values[0]['source']
    (directory/'results.json').write_text(json.dumps(checked,indent=2))
    print(json.dumps({key:value for key,value in checked.items() if key!='protected_inputs'}),flush=True)


if __name__=='__main__':
    main()

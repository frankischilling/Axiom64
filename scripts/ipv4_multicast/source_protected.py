# SPDX-License-Identifier: GPL-3.0-or-later
"""Reopen source-filter matrices under root and an ordinary identity."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from fetch import ROOT
from tcp6.inputs import digest, freeze
from ipv4_multicast_capture import require


def inventory(paths, prefix):
    result = {}
    for path in paths:
        require(not path.is_symlink(), 'protected source matrix regular input')
        meta = path.stat()
        result[str(path.relative_to(prefix))] = dict(sha256=digest(path), mode=stat.S_IMODE(meta.st_mode),
                                                    uid=meta.st_uid, gid=meta.st_gid)
    return result


def run(directory, output, domain='all'):
    require(os.geteuid() == 0, 'protected source matrix readback requires root and UID 65534')
    directory, output = Path(directory).resolve(), Path(output).resolve()
    require(all(path.is_relative_to((ROOT / 'build').resolve()) for path in (directory, output)) and
            not output.is_relative_to(directory) and not directory.is_relative_to(output),
            'protected source matrix separate owned build paths')
    output.mkdir(parents=True, exist_ok=False)
    frozen = output / 'reader-source'
    frozen.mkdir()
    source = freeze(frozen)
    originals = inventory([p for p in directory.rglob('*') if p.is_file()], directory)
    with tempfile.TemporaryDirectory(prefix='axiom-source-protected-') as temporary:
        scratch = Path(temporary)
        scratch.chmod(0o755)
        root = scratch / 'source'
        root.mkdir()
        sources = json.loads((frozen / 'source-inputs.json').read_text())
        with zipfile.ZipFile(frozen / 'source.zip') as archive:
            require(len(archive.namelist()) == len(sources) and set(archive.namelist()) == set(sources),
                    'protected complete source-filter reader archive')
            for name, expected in sources.items():
                path = PurePosixPath(name)
                require(not path.is_absolute() and '..' not in path.parts, 'protected bounded source path')
                body = archive.read(name)
                require(hashlib.sha256(body).hexdigest() == expected, 'protected original reader bytes')
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
                target.chmod(0o444)
        corpus = root / 'build/source-matrix'
        shutil.copytree(directory, corpus, copy_function=os.link)
        worker = scratch / 'reader.py'
        worker.write_text('''from pathlib import Path
import json
import os
import subprocess
import sys
root=Path(sys.argv[1]);out=Path(sys.argv[2]);domain=sys.argv[3];sys.path.insert(0,str(root/'scripts'))
from ipv4_multicast.source_matrix import admission,verify
corpus=root/'build/source-matrix';positive=verify(corpus,domain=domain)
native=[];index=json.loads((corpus/'source-matrix.json').read_text())
for spec in index['cases']:
    if not spec['native']:continue
    try:checked=admission(corpus/spec['path'],spec,index)
    except (ValueError,AssertionError,KeyError,IndexError,OSError) as error:
        native.append(dict(label=spec['label'],accepted=False,reason=type(error).__name__+': '+str(error)))
    else:native.append(dict(label=spec['label'],accepted=True,result=checked))
if domain=='all':assert all(row['accepted'] for row in native)
def command(name,args,label):
    with (out/(label+'.log')).open('xb') as log:
        completed=subprocess.run([sys.executable,'-B',str(root/'scripts/tests'/name),*args],cwd=root,stdout=log,stderr=subprocess.STDOUT)
    if completed.returncode:raise RuntimeError((out/(label+'.log')).read_text()[-8000:])
    return json.loads((out/label/'results.json').read_text())
delivery=command('ipv4_multicast_delivery_evidence_test.py',['--directory',str(corpus/'delivery-guest-dynamic-uefi-legacy'),
    '--native-directory',str(corpus/'delivery-linux-native'),'--output',str(out/'delivery-controls')],'delivery-controls')
assert delivery['serialized_reopened_controls']==36
matrix=command('ipv4_multicast_source_matrix_test.py',['--directory',str(corpus),'--domain',domain,
    '--output',str(out/'matrix-controls')],'matrix-controls')
assert matrix['serialized_reopened_controls']==8
report=[]
for scenario,case,count in (('settled','settled-guest-static-bios-modern',10),('queries','queries-guest-dynamic-uefi-legacy',14),
    ('mtu','mtu-guest-static-uefi-modern',17),('overlap','overlap-guest-dynamic-bios-legacy',19)):
    label=scenario+'-controls'
    result=command('ipv4_multicast_source_evidence_test.py',['--directory',str(corpus/case),'--output',str(out/label)],label)
    assert len(result['controls'])==count
    report.append(dict(scenario=scenario,controls=count))
(out/'result.json').write_text(json.dumps(dict(passed=True,uid=os.getuid(),domain=domain,positive=positive,
    native=native,delivery_controls=36,matrix_controls=8,report_controls=report,serialized_controls=104),indent=2)+'\\n')
''')
        worker.chmod(0o444)
        protected = [worker, *[p for p in root.rglob('*') if p.is_file()]]
        before = inventory(protected, scratch)
        require(all(row['uid'] == 0 and not row['mode'] & 0o022 for row in before.values()),
                'protected inputs root-owned and not writable by ordinary identities')
        (output / 'protected-before.json').write_text(json.dumps(before, indent=2) + '\n')
        readers = []
        for uid in (0, 65534):
            target = root / 'build' / ('reader-' + str(uid))
            target.mkdir()
            os.chown(target, uid, uid)
            command = [sys.executable, '-B', str(worker), str(root), str(target), domain]
            if uid:
                command = ['setpriv', '--reuid', str(uid), '--regid', str(uid), '--clear-groups', *command]
            with (output / ('reader-' + str(uid) + '.log')).open('xb') as log:
                completed = subprocess.run(command, cwd=scratch, stdout=log, stderr=subprocess.STDOUT)
            require(before == inventory(protected, scratch), 'protected source matrix bytes owners and modes unchanged')
            require(originals == inventory([p for p in directory.rglob('*') if p.is_file()], directory),
                    'original source matrix bytes owners and modes unchanged')
            retained = output / ('reader-' + str(uid))
            retained.mkdir()
            summaries = {target / (name + '-controls') for name in
                         ('delivery', 'matrix', 'settled', 'queries', 'mtu', 'overlap')}
            for path in target.rglob('*'):
                keep = ((path.suffix == '.zip' and path.name != 'source.zip') or
                        (path.suffix == '.log' and path.parent == target) or
                        (path.name == 'result.json' and path.parent == target) or
                        (path.name == 'results.json' and path.parent in summaries))
                if path.is_file() and keep:
                    destination = retained / path.relative_to(target)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
            completed.check_returncode()
            readers.append(json.loads((target / 'result.json').read_text()))
            print('IPV4_SOURCE_PROTECTED_READER_PASS uid=' + str(uid), flush=True)
        (output / 'protected-after.json').write_text(json.dumps(inventory(protected, scratch), indent=2) + '\n')
    result = dict(passed=True, domain=domain, reader_source=source, readers=readers,
                  protected_inputs_unchanged=len(before), original_runtime_files_unchanged=len(originals),
                  serialized_controls_each=104, root_and_uid65534=True,
                  full_native_guest_acceptance=domain == 'all', full_feature_acceptance=False)
    (output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--domain', choices=('all', 'guest'), default='all')
    args = parser.parse_args()
    result = run(args.directory, args.output, args.domain)
    print(json.dumps({k: v for k, v in result.items() if k != 'readers'}, indent=2))


if __name__ == '__main__':
    main()

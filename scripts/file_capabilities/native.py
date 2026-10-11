# SPDX-License-Identifier: GPL-3.0-or-later
"""Run all three linkages against Linux in owned private mount namespaces."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from build_musl import loader
from build_libcap import ensure as libcap
from file_capabilities.common import digest, save, snapshot, volume
from file_capabilities.disk import verify_persist
from file_capabilities.guest import FORMATS


def isolated(args):
    if args.filesystem == 'tmpfs':
        command = ['mount', '-t', 'tmpfs', '-o', 'mode=1777', 'none', '/tmp']
    else:
        command = ['mount', '-t', 'ext2', '-o', 'loop', str(args.disk), '/tmp']
    subprocess.run(command, check=True)
    try:
        os.environ['FILECAP_MOUNT_TARGET'] = '/tmp'
        os.environ['FILECAP_PERSIST_DIR'] = '/tmp/filecap-persisted'
        os.environ['FILECAP_TOOLS'] = str(libcap('native' if args.linkage == 'native' else 'build'))
        if args.filesystem == 'tmpfs':
            os.environ['FILECAP_SHARED_MAPPING'] = '1'
        else:
            os.environ['FILECAP_EXT2_BLOCK_SIZE'] = str(args.block)
        if args.linkage != 'native':
            source = loader()
            destination = Path('/lib/ld-musl-x86_64.so.1').resolve()
            if not destination.is_file():
                raise RuntimeError('native musl loader bind target does not exist')
            subprocess.run(['mount', '--bind', str(source), str(destination)], check=True)
            if digest(source) != digest(destination):
                raise RuntimeError('native nested exec does not use the pinned musl loader')
            print('FILECAP_NATIVE_LOADER sha256=' + digest(destination), flush=True)
        (args.output / (args.label + '-mountinfo.log')).write_text(Path('/proc/self/mountinfo').read_text())
        executable = ROOT / 'build' / ('file-capabilities-' + args.linkage)
        subprocess.run([str(executable)], check=True)
    finally:
        subprocess.run(['umount', '/tmp'], check=True)
    if args.filesystem == 'ext2':
        subprocess.run(['mount', '-t', 'ext2', '-o', 'loop', str(args.disk), '/tmp'], check=True)
        try:
            subprocess.run([str(executable), '--verify-persist', '/tmp/filecap-persisted'], check=True)
        finally:
            subprocess.run(['umount', '/tmp'], check=True)


def run(args, label, linkage, form):
    disk = args.output / (label + '.img') if form else None
    if form:
        volume(disk, form[0], form[1], form[2] == 'original')
    command = ['unshare', '--mount', '--propagation', 'private', sys.executable, str(Path(__file__).resolve()),
               '--isolated', '--output', str(args.output), '--label', label, '--linkage', linkage,
               '--filesystem', 'ext2' if form else 'tmpfs']
    if disk:
        command += ['--disk', str(disk), '--block', str(form[0])]
    start, timed_out = time.monotonic_ns(), False
    started_ns = time.time_ns()
    log = args.output / (label + '.log')
    with log.open('wb') as stream:
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, cwd=ROOT, start_new_session=True)
        try:
            process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    text = log.read_text(errors='replace')
    phases = ('XATTR', 'FORMAT', 'CONTENT', 'ADMIN', 'EXEC', 'TOOLS', 'MOUNT', 'TEST', 'PERSIST_VERIFY')
    missing = [phase for phase in phases if 'FILECAP_' + phase + '_PASS ' not in text]
    if form and 'FILECAP_PERSIST_REBOOT_PASS ' not in text:
        missing.append('fresh native ext2 mount')
    record = dict(label=label, linkage=linkage, filesystem='ext2' if form else 'tmpfs', format=form,
                  command=command, started_ns=started_ns, elapsed_ns=time.monotonic_ns() - start,
                  timeout_seconds=120, timed_out=timed_out, returncode=process.returncode,
                  log=log.name, log_sha256=digest(log), missing=missing,
                  passed=process.returncode == 0 and not timed_out and not missing and
                  'FILECAP_TEST_FAIL ' not in text)
    save(args.output / (label + '-run.json'), record)
    print('FILECAP_NATIVE label=' + label + ' passed=' + str(record['passed']), flush=True)
    if not record['passed']:
        print(text[-5000:], flush=True)
        raise RuntimeError('native file capability comparison failed; no profile was skipped: ' + label)
    if disk:
        record['host'] = verify_persist(disk, args.output, label, linkage, native=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'build/file-capabilities/native')
    parser.add_argument('--filesystem', choices=('tmpfs', 'ext2', 'both'), default='both')
    parser.add_argument('--linkage', choices=('native', 'static', 'dynamic', 'all'), default='all')
    parser.add_argument('--isolated', action='store_true')
    parser.add_argument('--label')
    parser.add_argument('--disk', type=Path)
    parser.add_argument('--block', type=int)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('private native mounts require root after building the clients')
    args.output = args.output.resolve()
    if args.isolated:
        isolated(args)
        return
    args.output.mkdir(parents=True, exist_ok=False)
    # CI restores target products onto another runner. Rebuild the glibc client
    # against the exact native startup/library inputs captured below.
    subprocess.run(['make', '-s', '-B', 'build/file-capabilities-native'], cwd=ROOT, check=True)
    snapshot(args.output, native=True)
    rows = []
    for linkage in ('native', 'static', 'dynamic') if args.linkage == 'all' else (args.linkage,):
        forms = ([None] if args.filesystem in ('tmpfs', 'both') else []) + (
                 list(FORMATS) if args.filesystem in ('ext2', 'both') else [])
        for form in forms:
            label = 'linux-' + linkage + '-' + ('-'.join(map(str, form)) if form else 'tmpfs')
            rows.append(run(args, label, linkage, form))
            save(args.output / 'results.json', rows)


if __name__ == '__main__':
    main()

"""Revalidate real saved hints after a fresh kernel boots the same ext2 root."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from disk_root import archive_entries, bootstrap, populate
from ext2_test import check_fs, debugfs, dump
from fetch import ROOT
from manager_test import fixture, run


def seed(linkage):
    fixture(linkage, 'persist-prime', '/etc', build_image=False)
    entries = archive_entries(ROOT / 'build/rootfs-network.cpio')
    destination = ROOT / 'build' / f'manager-persistent-{linkage}-seed.raw'
    with tempfile.TemporaryDirectory(prefix='axiom64-manager-root-') as directory:
        stage = Path(directory)
        populate(stage, entries)
        with destination.open('wb') as output:
            output.truncate(32 * 1024 * 1024)
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext2', '-b', '4096', '-I', '128',
                        '-O', 'none,filetype,sparse_super,large_file', '-N', '1024',
                        '-E', 'root_owner=0:0,lazy_itable_init=0', '-d', str(stage), str(destination)],
                       check=True)
    commands = [f'set_inode_field {json.dumps(name)} {field} 0'
                for name in ['/', '/lost+found', *('/' + name for name in sorted(entries))]
                for field in ('uid', 'gid')]
    subprocess.run(['debugfs', '-w', '-f', '-', str(destination)], input='\n'.join(commands) + '\n',
                   text=True, check=True, capture_output=True)
    check_fs(destination, f'manager-persistent-{linkage}-seed')
    bootstrap(ROOT / 'build/rootfs-bootstrap.cpio')
    name = f'axiom64-manager-persistent-{linkage}.iso'
    subprocess.run(['python3', 'scripts/image.py', '--test', '--suite', 'network',
                    '--root-device', '/dev/vda', '--output-name', name], cwd=ROOT, check=True)
    fixture(linkage, 'persist-reboot', '/etc', build_image=False)
    reboot = archive_entries(ROOT / 'build/rootfs-network.cpio')['etc/net-test.sh'][1]
    return destination, ROOT / 'build' / name, reboot


def exists(disk, path):
    return debugfs(disk, f'stat {path}').startswith('Inode:')


def saved_snapshot(disk, linkage, label):
    directory = f'/etc/manager-persistent-{linkage}/saved'
    info = debugfs(disk, f'stat {directory}')
    if 'Mode:  0700' not in info or 'User:     0' not in info:
        raise RuntimeError('host sees unsafe saved directory metadata')
    output = {}
    for leaf in ('eth0.conf', 'eth0.lease', 'eth1.lease'):
        path = directory + '/' + leaf
        info = debugfs(disk, f'stat {path}')
        if 'Type: regular' not in info or 'Mode:  0600' not in info or 'User:     0' not in info or 'Links: 1' not in info:
            raise RuntimeError('host sees unsafe saved input metadata: ' + path)
        output[leaf] = dump(disk, path, label)
    for lane in range(2):
        expected = (f'axiom64-lease=1\nmac=52:54:00:12:34:{0x10 + lane:02x}\n'
                    f'address=10.23.{lane + 1}.40\n').encode()
        if output[f'eth{lane}.lease'] != expected:
            raise RuntimeError('host hint differs or retains more than version/MAC/address')
    for path in (f'/run/manager-persistent-{linkage}', f'/run/manager-resolver-persistent-{linkage}'):
        if exists(disk, path):
            raise RuntimeError('volatile runtime contents leaked into the persistent root')
    return output


def boot_pair(linkage, firmware, transport, source, image, script, timeout):
    label = f'manager-persistent-{linkage}-{firmware}-{transport}'
    disk = ROOT / 'build' / (label + '.raw')
    shutil.copyfile(source, disk)
    report = dict(linkage=linkage, firmware=firmware, transport=transport, disk=disk.name,
                  phases=[], passed=False, error=None)
    try:
        prime = run(linkage, 'persist-prime', firmware, transport, timeout, root_disk=disk, image=image)
        report['phases'].append(prime)
        if not prime['passed']:
            raise RuntimeError('first real ext2 root boot failed')
        check_fs(disk, label + '-prime')
        before = saved_snapshot(disk, linkage, label + '-prime')
        replacement = ROOT / 'build' / (label + '-script')
        replacement.write_bytes(script)
        replacement.chmod(0o755)
        debugfs(disk, 'rm /etc/net-test.sh', write=True)
        debugfs(disk, f'write {replacement} /etc/net-test.sh', write=True)
        if dump(disk, '/etc/net-test.sh', label + '-reboot-script') != script:
            raise RuntimeError('host failed to install the second observer phase')
        reboot = run(linkage, 'persist-reboot', firmware, transport, timeout, root_disk=disk, image=image)
        report['phases'].append(reboot)
        if not reboot['passed']:
            raise RuntimeError('second fresh-kernel ext2 root boot failed')
        for lane in range(2):
            old = prime['counts'][lane]['transaction']
            new = reboot['counts'][lane]['transaction']
            if not old or not new or old == new:
                raise RuntimeError('fresh boot failed to choose a new validation transaction')
        directory = f'/etc/manager-persistent-{linkage}/saved'
        if dump(disk, directory + '/eth0.conf', label + '-reboot') != before['eth0.conf']:
            raise RuntimeError('saved profile bytes changed across reboot')
        if any(exists(disk, directory + f'/eth{lane}.lease') for lane in range(2)):
            raise RuntimeError('normal second-boot signal teardown retained a released hint')
        if any(exists(disk, path) for path in (f'/run/manager-persistent-{linkage}',
                                              f'/run/manager-resolver-persistent-{linkage}')):
            raise RuntimeError('second-boot runtime contents leaked into persistent root')
        report['fsck'] = check_fs(disk, label + '-reboot')
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
    print(json.dumps(report), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linkage', choices=['static', 'dynamic', 'both'], default='both')
    parser.add_argument('--firmware', choices=['bios', 'uefi', 'both'], default='both')
    parser.add_argument('--transport', choices=['modern', 'legacy', 'both'], default='both')
    parser.add_argument('--timeout', type=float, default=120)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('timeout must be positive')
    results = []
    for linkage in ['static', 'dynamic'] if args.linkage == 'both' else [args.linkage]:
        source, image, script = seed(linkage)
        for firmware in ['bios', 'uefi'] if args.firmware == 'both' else [args.firmware]:
            for transport in ['modern', 'legacy'] if args.transport == 'both' else [args.transport]:
                result = boot_pair(linkage, firmware, transport, source, image, script, args.timeout)
                results.append(result)
                (ROOT / 'build/manager-persistent-results.json').write_text(json.dumps(results, indent=2) + '\n')
                if not result['passed']:
                    raise SystemExit('Saved network state did not pass a fresh ext2-root boot')


if __name__ == '__main__':
    main()

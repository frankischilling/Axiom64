# SPDX-License-Identifier: GPL-3.0-or-later
"""Publish actual root-created backend evidence without changing its bytes."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / 'scripts/ci/storage_evidence.sh'


def main():
    assert os.geteuid() == 0, 'run this isolated ownership comparison with sudo'
    spec = importlib.util.spec_from_file_location('backend', ROOT / 'scripts/account_logbook_rotation_block.py')
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    with tempfile.TemporaryDirectory(prefix='axiom64-storage-publication-', dir='/tmp') as temporary:
        workspace = Path(temporary)
        workspace.chmod(0o755)
        os.chown(workspace, 1001, 1001)
        (workspace / 'build').mkdir()
        relative = 'build/account-management-publication-control'
        evidence = workspace / relative
        evidence.mkdir()
        disk, trace = evidence / 'disk.raw', evidence / 'block.jsonl'
        with disk.open('wb') as stream:
            stream.truncate(1024 * 1024)
        for key, value in dict(disk=str(disk), trace=str(trace), **{
                'control-offset': '0', 'control-marker': b'A'.hex(), 'control-end-marker': '',
                'cache-model': 'writeback', 'fault-operation': 'write', 'fault-request': '0',
                'fault-mode': 'observe', 'gate': ''}).items():
            backend.config(key, value)
        backend.config_complete()
        os.close(backend._trace)
        private = evidence / 'private'
        private.mkdir(mode=0o700)
        (private / 'retained.log').write_bytes(b'actual owned observation\n')
        (private / 'retained.log').chmod(0o600)
        outside = workspace / 'outside-target'
        outside.write_bytes(b'outside the completed evidence\n')
        (evidence / 'outside-link').symlink_to(outside)
        values = {path.relative_to(evidence).as_posix(): path.read_bytes()
                  for path in (disk, trace, private / 'retained.log')}
        assert trace.stat().st_uid == 0 and trace.stat().st_mode & 0o777 == 0o600
        # Without the publication step, this is the original hosted call chain.
        if PUBLISH.exists():
            subprocess.run(['bash', str(PUBLISH), '1001', '1001', relative], cwd=workspace, check=True)
        program = ('import json,sys,zipfile; from pathlib import Path; '
                   'root=Path(sys.argv[1]); names=json.loads(sys.argv[2]); '
                   'z=zipfile.ZipFile(root.parent.parent / "uploaded.zip", "x"); '
                   '[z.write(root/name,name) for name in names]; z.close()')
        result = subprocess.run([sys.executable, '-c', program, str(evidence), json.dumps(list(values))],
                                capture_output=True, text=True, user=1001, group=1001, extra_groups=[])
        assert result.returncode == 0, result.stderr
        with zipfile.ZipFile(workspace / 'uploaded.zip') as archive:
            assert {name: archive.read(name) for name in archive.namelist()} == values
        assert all((evidence / name).read_bytes() == value for name, value in values.items())
        assert all((evidence / name).stat().st_uid == 1001 for name in values)
        assert outside.stat().st_uid == 0 and outside.read_bytes() == b'outside the completed evidence\n'
        assert trace.stat().st_mode & 0o777 == 0o600
        guard = workspace / 'build/account-management-guard'
        guard.mkdir()
        (guard / 'proof').write_bytes(b'untouched\n')
        rejected = 0
        for bad in ('build', '../outside-target', str(outside), 'build/account-management-guard/../other',
                    'build/unrelated', 'build/account-management-guard/outside-link'):
            result = subprocess.run(['bash', str(PUBLISH), '1001', '1001',
                                     'build/account-management-guard', bad], cwd=workspace,
                                    capture_output=True, text=True)
            assert result.returncode != 0 and guard.stat().st_uid == 0
            rejected += 1
        (workspace / 'build/account-management-link').symlink_to(guard, target_is_directory=True)
        result = subprocess.run(['bash', str(PUBLISH), '1001', '1001', 'build/account-management-link'],
                                cwd=workspace, capture_output=True, text=True)
        assert result.returncode != 0 and guard.stat().st_uid == 0
        rejected += 1
        subprocess.run(['bash', str(PUBLISH), '1001', '1001', 'build/account-management-absent'],
                       cwd=workspace, check=True)
        assert not (workspace / 'build/account-management-absent').exists()
    print('ACCOUNT_STORAGE_PUBLICATION_PASS actual_backend_trace=1 ordinary_zip_reader=1 '
          'bytes_unchanged=1 private_modes_preserved=1 rejected_paths=' + str(rejected))


if __name__ == '__main__':
    main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise real procfs policy ownership across an exec and a new namespace."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fetch import ROOT
from native_icmp_policy import InitialIcmpLimits, InheritedIcmpLimits
from native_icmp_preflight import NativeIcmpPreflight, POLICY
from native_ipv4_state import NativeIpv4State


def child(directory, handles):
    library = ctypes.CDLL(None, use_errno=True)
    assert library.unshare(0x40000000) == 0
    inherited = InheritedIcmpLimits(handles) if handles else None
    directory.mkdir()
    state = NativeIpv4State(directory, global_policy=inherited)
    state.snapshot('actual private namespace with original policy ownership')
    result = state.close()
    assert result['complete'] and result['read_errors'] == 0
    primer = NativeIcmpPreflight(directory, global_policy=inherited)
    primer.policy('policy_before')
    primer.policy('policy_after')
    assert all(primer.evidence[name]['values'] == POLICY for name in ('policy_before', 'policy_after'))
    controls = 0
    if inherited is not None:
        assert primer.evidence['schema'] == 2
        snapshot = json.loads((directory / 'native-kernel-state.jsonl').read_text())
        assert len(snapshot['global_sources']) == 2
        original = json.loads(handles.read_text())
        bad = directory / 'bad-handles.json'
        wrong = dict(original, namespace=os.readlink('/proc/self/ns/net'))
        bad.write_text(json.dumps(wrong))
        try:
            InheritedIcmpLimits(bad)
        except ValueError:
            controls += 1
        else:
            raise AssertionError('same-namespace ownership accepted')
        with (directory / 'false-provider').open('w+b') as source:
            source.write(b'1000\n')
            source.flush()
            wrong = dict(original, descriptors=dict(original['descriptors'], icmp_msgs_per_sec=source.fileno()))
            bad.write_text(json.dumps(wrong))
            try:
                InheritedIcmpLimits(bad)
            except ValueError:
                controls += 1
            else:
                raise AssertionError('regular file substituted for actual read-only procfs policy')
        descriptor = inherited.descriptors['icmp_msgs_per_sec']
        os.close(descriptor)
        try:
            primer.policy('policy_after')
        except OSError:
            controls += 1
        else:
            raise AssertionError('closed global handle accepted')
        assert controls == 3
    print(json.dumps(dict(passed=True, actual_policy_values=POLICY, original_state_files_complete=True,
        exec_inheritance=True, private_namespace=True, global_controls=2 if inherited else 0,
        rejected_controls=controls, host_policy_not_written=True)), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/native-icmp-policy-test')
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--handles', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    assert os.geteuid() == 0
    if args.child:
        child(args.directory, args.handles)
        return
    args.directory.mkdir(parents=True, exist_ok=False)
    with InitialIcmpLimits(args.directory) as limits:
        command = [sys.executable, '-B', __file__, '--child', '--directory', str(args.directory / 'child')]
        if limits.path is not None:
            command += ['--handles', str(limits.path)]
        subprocess.run(command, check=True, pass_fds=limits.pass_fds)


if __name__ == '__main__':
    main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Require complete administration/storage executions and every observed device fault."""
import argparse
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import re

from account_rotation_storage_coverage import digest, identity, require

ROOT = Path(__file__).resolve().parents[1]
DIMENSIONS = (('build', 'runtime'), ('static', 'dynamic'), ('bios', 'uefi'), ('modern', 'legacy'))
MODES = ('eio', 'pause-before', 'pause-after')
LABELS = {'intent-audit-data', 'intent-audit-published', 'intent-audit-flushed', 'passwd-staged',
          'shadow-staged', 'home-created-before-publication', 'complete-generation-published',
          'older-generation-collected', 'completion-audit-published'}


def validate_index(index):
    require(index['format'] == 1 and index['retained_execution_verified'] is True,
            'not a collected administration index')
    scope = index['scope']
    require(len(scope) == 4 and all(value in choices for value, choices in zip(scope, DIMENSIONS)),
            'invalid administration scope')
    require(index['guest_timeout_seconds'] == 120, 'administration deadline changed')
    require(identity(index['source_inputs']) == index['source_identity'], 'altered administration source binding')
    require(index['evidence_files'] and all(re.fullmatch(r'[0-9a-f]{64}', value)
                                          for value in index['evidence_files'].values()),
            'missing retained administration bindings')
    if index['kind'] == 'clean-storage':
        require(index['cases'] == ['clean/prepare', 'clean/exercise', 'clean/concurrent', 'clean/verify',
                                   'storage/prepare', 'storage/readonly', 'storage/full'],
                'missing administration concurrency, reboot or storage control')
        require(index['fresh_boot_equality'] and index['readonly_bytes_unchanged'] and
                index['counts'] == dict(boots=7, faults=0, vm_kills=0, device_errors=0),
                'incomplete clean/storage execution')
        return 'clean-storage', tuple(scope)
    require(index['kind'] == 'fault' and index['cache'] in ('writeback', 'writethrough') and
            index['fault_modes'] == list(MODES), 'missing administration fault model or modes')
    targets = index['physical_targets']
    labels = [label for target in targets for label in target['labels']]
    keys = {(value['operation'], value['request']) for value in targets}
    require(len(keys) == len(targets) and len(labels) == len(set(labels)) and LABELS <= set(labels),
            'duplicate or missing observed administration phase')
    require(all(value['operation'] in ('write', 'flush') and type(value['request']) is int and
                value['request'] > 0 and value['labels'] for value in targets),
            'invalid administration physical target')
    actual = [(value['operation'], value['request'], value['mode']) for value in index['cases']]
    require(len(actual) == len(set(actual)) and set(actual) ==
            {(operation, request, mode) for operation, request in keys for mode in MODES},
            'missing, duplicate or unexpected administration fault')
    count = len(keys)
    require(index['counts'] == dict(boots=1 + (count * 3 + 1) * 2, faults=count * 3,
                                    vm_kills=count * 2, device_errors=count),
            'actual administration execution counts differ')
    return 'fault', (*scope, index['cache'])


def verify_matrix(indices):
    require(bool(indices), 'no administration storage indices')
    sources, products = indices[0]['source_inputs'], indices[0]['kernel_init_sha256']
    scopes = {'clean-storage': set(), 'fault': set()}
    totals = dict(boots=0, faults=0, vm_kills=0, device_errors=0)
    for index in indices:
        kind, scope = validate_index(index)
        require(scope not in scopes[kind], 'duplicate administration variant')
        scopes[kind].add(scope)
        require(index['source_inputs'] == sources and index['kernel_init_sha256'] == products,
                'administration variants used different source or kernel/init inputs')
        for name in totals:
            totals[name] += index['counts'][name]
    require(scopes['clean-storage'] == set(itertools.product(*DIMENSIONS)),
            'incomplete clean/storage provider/linkage/firmware/transport matrix')
    require(scopes['fault'] == set(itertools.product(*DIMENSIONS, ('writeback', 'writethrough'))),
            'incomplete administration device-fault matrix')
    return dict(passed=True, matrix_complete=True, clean_storage_variants=16, fault_variants=32,
                counts=totals, source_identity=identity(sources), kernel_init_sha256=products)


class Corpus:
    def __init__(self, directory, campaign):
        self.directory = directory.resolve()
        self.read = lambda path: json.loads(path.read_text())
        self.receipt = self.read(self.directory / 'receipt.json')
        require(all(self.receipt[name] is True for name in
                    ('passed', 'terminal', 'source_stable', 'actual_commands', 'journaled')) and
                not self.receipt['wrapped'] and self.receipt['timeout_seconds'] == 120 and
                self.receipt['campaign'] == campaign, 'incomplete or changed administration producer')
        self.sources = self.read(self.directory / 'source-inputs.json')
        require(digest(self.directory / 'source-inputs.json') ==
                self.receipt['original_source_manifest_sha256'], 'source manifest changed')
        for name, expected in self.sources.items():
            path = Path(name)
            require(not path.is_absolute() and '..' not in path.parts and '.local' not in path.parts and
                    digest(ROOT / path) == expected, 'executed administration source differs')
        self.rows = self.read(self.directory / 'results.json')
        require(len(self.rows) == self.receipt['phases'], 'administration result index differs')
        scopes = {tuple(row[name] for name in ('provider', 'linkage', 'firmware', 'transport'))
                  for row in self.rows}
        require(len(scopes) == 1, 'collect one actual administration variant')
        self.scope = next(iter(scopes))
        require(all(value in choices for value, choices in zip(self.scope, DIMENSIONS)), 'invalid producer scope')

    def bind(self, path, expected=None):
        require(path.is_file() and not path.is_symlink() and
                path.resolve().is_relative_to(self.directory), 'missing or escaped retained evidence')
        actual = digest(path)
        require(expected is None or expected == actual, 'retained administration hash differs: ' + str(path))
        return actual

    def archive(self, record):
        path = Path(record['path'])
        self.bind(path, record['compressed']['sha256'])
        require(path.stat().st_size == record['compressed']['bytes'] and
                record['original']['bytes'] == 32 * 1024 * 1024, 'administration volume geometry differs')
        with gzip.open(path, 'rb') as stream:
            raw = stream.read(32 * 1024 * 1024 + 1)
        require(len(raw) == record['original']['bytes'] and
                hashlib.sha256(raw).hexdigest() == record['original']['sha256'],
                'retained administration volume bytes differ')
        return record['original']['sha256']

    def guest(self, row, folder, phase, *, power_cut=False):
        self.bind(folder / 'guest.log', row['log_sha256'])
        require(not row['timed_out'] and 0 < row['elapsed_ns'] < 120_000_000_000 and
                row['returncode'] == (-9 if power_cut else 1), 'actual guest failed or exceeded its deadline')
        command = row['command']
        require(command[:9] == ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max', '-m', '256M', '-nic', 'none']
                and not any(value in command for value in ('-icount', '-accel', '-rtc')),
                'administration guest execution or clock differs')
        self.bind(Path(command[command.index('-cdrom') + 1]))
        devices = [value for value in command if value.startswith('virtio-blk-pci,drive=management,')]
        require(len(devices) == 1 and
                ('disable-legacy=on' if self.scope[3] == 'modern' else 'disable-modern=on') in devices[0].split(','),
                'actual administration transport differs')
        text = (folder / 'guest.log').read_text().replace('\r\n', '\n')
        require('Firmware: ' + self.scope[2].upper() in text and
                'virtio-blk: disk=0 transport=' + self.scope[3] + ' sectors=65536 readonly=' in text and
                not any(value in text for value in ('PANIC:', 'FAULT pid=', 'ACCOUNT_MANAGEMENT_EXT2_FAIL')),
                'guest reported a failure or different firmware')
        if not power_cut:
            require(text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                    text.splitlines().count('AXIOM64_EXIT status=0') == 1 and
                    len(re.findall(r'^ACCOUNT_MANAGEMENT_EXT2_PASS phase=' + phase + r' [^\n]*\n', text, re.M)) == 1,
                    'actual administration success record is incomplete')
        return text

    def fsck(self, row, folder):
        require(row['passed'] and row['returncode'] == 0 and not row['timed_out'] and
                row['command'][:3] == ['e2fsck', '-f', '-n'] and not row['inconsistency_diagnostics'],
                'strict actual administration filesystem check failed')
        path = folder / row['log']
        self.bind(path, row['log_sha256'])
        text = path.read_text()
        require(all('Pass ' + str(number) + ':' in text for number in range(1, 6)) and
                not re.search(r'count wrong|bitmap differences|Fix\?|Clear\?|still has errors', text, re.I),
                'native administration postcheck is incomplete or found damage')

    def evidence(self):
        return {path.relative_to(self.directory).as_posix(): self.bind(path)
                for path in self.directory.rglob('*') if path.is_file()}


def base_index(corpora):
    sources = dict(corpora[0].sources)
    require(all(corpus.sources == sources and corpus.scope == corpora[0].scope for corpus in corpora),
            'clean and storage runs used different inputs or variants')
    for name in ('scripts/account_management_storage_coverage.py', 'scripts/account_rotation_storage_coverage.py',
                 'scripts/account_storage_shards.py'):
        sources[name] = digest(ROOT / name)
    return dict(format=1, retained_execution_verified=True, scope=list(corpora[0].scope),
                guest_timeout_seconds=120, source_inputs=sources, source_identity=identity(sources),
                corpus_names=[corpus.directory.name for corpus in corpora],
                kernel_init_sha256={name: digest(ROOT / name) for name in ('build/axiom64.elf', 'build/init')},
                evidence_files={str(number) + '/' + name: value for number, corpus in enumerate(corpora)
                                for name, value in corpus.evidence().items()})


def collect_clean(clean, storage):
    clean, storage = Corpus(clean, 'clean'), Corpus(storage, 'storage')
    require([row['phase'] for row in clean.rows] == ['prepare', 'exercise', 'concurrent', 'verify'] and
            [row['phase'] for row in storage.rows] == ['prepare', 'readonly', 'full'],
            'missing actual administration, concurrency or storage control')
    for corpus in (clean, storage):
        profile = corpus.directory / '-'.join(corpus.scope[:2]) / '-'.join(corpus.scope[2:])
        for row in corpus.rows:
            require(row['passed'], 'actual administration phase failed')
            folder = profile / row['phase']
            text = corpus.guest(row, folder, row['phase'])
            corpus.fsck(row['fsck'], folder)
            if corpus is clean:
                require(corpus.archive(row['retained_phase_disk']) == row['actual_device_disk_sha256'] ==
                        row['host_state']['disk_sha256'], 'clean administration disk differs')
                if row['phase'] == 'concurrent':
                    require('ACCOUNT_MANAGEMENT_EXT2_BLOCKED commands=12 evidence=owned_database_flock_and_proc_S\n' in text
                            and 'ACCOUNT_MANAGEMENT_EXT2_PASS phase=concurrent commands=25 observations=5\n' in text,
                            'actual concurrent command barrier or observations missing')
            elif row['phase'] != 'prepare':
                require(corpus.archive(row['retained_disk']) == row['actual_device_disk_sha256'] ==
                        row['host_state']['disk_sha256'], 'storage control actual disk differs')
        if corpus is storage:
            corpus.archive(corpus.rows[-1]['retained_seed'])
    final = clean.rows[-1]
    require(final['fresh_kernel_identical_generation_and_home_metadata'] and all(
            clean.rows[-2]['host_state'][name] == final['host_state'][name] for name in ('current', 'files', 'metadata')),
            'fresh kernel changed the account generation or home metadata')
    require(clean.archive(final['retained_final_disk']) == final['actual_device_disk_sha256'],
            'final administration disk differs')
    require(storage.rows[1]['readonly_bytes_unchanged'], 'read-only storage control changed bytes')
    text = (storage.directory / '-'.join(storage.scope[:2]) / '-'.join(storage.scope[2:]) / 'full/guest.log').read_text()
    require('ACCOUNT_MANAGEMENT_EXT2_ENOSPC written=' in text and 'errno=28' in text,
            'actual full-volume failure missing')
    index = base_index([clean, storage])
    index.update(kind='clean-storage', cases=['clean/' + row['phase'] for row in clean.rows] +
                 ['storage/' + row['phase'] for row in storage.rows], fresh_boot_equality=True,
                 readonly_bytes_unchanged=True, counts=dict(boots=7, faults=0, vm_kills=0, device_errors=0))
    validate_index(index)
    return index


def request_prefix(events, operation, request):
    result = []
    for event in events:
        if event['event'] == 'request':
            result.append([event['operation'], event.get('offset'), event.get('bytes')])
            if event['operation'] == operation and event['index'] == request:
                return result
    raise ValueError('selected actual administration request is missing')


def collect_fault(directory):
    corpus = Corpus(directory, 'fault')
    profile = corpus.directory / '-'.join(corpus.scope[:2]) / '-'.join(corpus.scope[2:])
    prepare = corpus.rows[0]
    require(prepare['phase'] == 'prepare', 'actual administration preparation missing')
    corpus.guest(prepare, profile / 'prepare', 'prepare')
    corpus.fsck(prepare['fsck'], profile / 'prepare')
    rows = corpus.read(corpus.directory / 'fault-results.json')
    baseline = [row for row in rows if row['fault_mode'] == 'observe']
    require(len(baseline) == 1, 'collect one administration cache baseline')
    baseline = baseline[0]
    cache = baseline['cache_model']
    observed = corpus.read(profile / ('baseline-' + cache) / 'observed-phases.json')
    require(observed == baseline['observed_phases'] and LABELS <= set(observed),
            'actual baseline lacks required administration phases')
    targets = {}
    for label, value in observed.items():
        targets.setdefault((value['operation'], value['request']), []).append(label)
    from account_logbook_rotation_block import trace_events
    baseline_trace = trace_events(profile / ('baseline-' + cache) / 'block.jsonl')
    require(len(rows) == corpus.receipt['fault_cells'] and len(corpus.rows) == len(rows) + 1 and
            set(corpus.directory.rglob('result.json')) == {profile / row['phase'] / 'result.json' for row in rows},
            'actual administration attempts are missing from the index')
    cases = []
    for row in rows:
        folder = profile / row['phase']
        require(row['passed'] and row['actual_unmodified_command'] and not row['wrapped'] and
                row['cache_model'] == cache and
                corpus.read(folder / 'result.json') == row, 'failed or changed actual fault result')
        mode = row['fault_mode']
        corpus.guest(row['run'], folder, 'attempt', power_cut=mode.startswith('pause-'))
        corpus.bind(folder / 'block.jsonl', row['run']['trace_sha256'])
        events = trace_events(folder / 'block.jsonl')
        interrupted = corpus.archive(row['retained_interrupted'])
        require(interrupted == row['actual_device_disk_sha256'], 'interrupted actual disk differs')
        oracle = row['native_journal_selection_oracle']
        require(all(oracle[name] is True for name in ('passed', 'terminal', 'journal_only',
                    'observation_copy_only', 'guest_input_unchanged')) and oracle['guest_input_sha256'] == interrupted
                and oracle['command'][1:4] == ['-y', '-E', 'journal_only'], 'actual journal oracle or input differs')
        corpus.bind(folder / 'journal-oracle.log', oracle['log_sha256'])
        require(corpus.read(folder / 'journal-oracle.json') == oracle, 'journal oracle record differs')
        recovery = folder / 'recovery'
        text = corpus.guest(row['recovery'], recovery, 'recover')
        exported = {name: value for name, value in re.findall(
            r'^ACCOUNT_MANAGEMENT_EXT2_DATA phase=recovered name=(passwd|group|shadow) hex=([0-9a-f]+)\n', text, re.M)}
        require({name: hashlib.sha256(bytes.fromhex(value)).hexdigest() for name, value in exported.items()} ==
                oracle['selected_files'], 'guest pre-retry selection differs from Linux journal replay')
        require(corpus.archive(row['retained_final']) == row['recovery']['actual_device_disk_sha256'],
                'actual recovered administration disk differs')
        corpus.archive(row['retained_armed'])
        corpus.fsck(row['post_recovery_fsck'], recovery)
        if mode == 'observe':
            require(row == baseline, 'unexpected second administration baseline')
            continue
        operation, request = row['fault_operation'], row['fault_request']
        require(row['baseline_request_prefix_exact'] and request_prefix(events, operation, request) ==
                request_prefix(baseline_trace, operation, request), 'actual administration request prefix differs')
        injected = [event for event in events if event['event'] == 'injected']
        trace = folder / 'virtio.trace'
        corpus.bind(trace, row['virtio_trace_sha256'])
        failures = len(re.findall(r'virtio_blk_req_complete .*?status 1\b', trace.read_text()))
        if mode == 'eio':
            require(len(injected) == failures == row['failed_virtio_completions'] == 1 and
                    injected[0]['operation'] == operation and injected[0]['index'] == request,
                    'actual failed administration device completion missing')
        else:
            paused = [event for event in events if event['event'] == 'paused']
            require(mode in MODES and len(paused) == 1 and paused[0] == row['actual_pause'] and
                    paused[0]['operation'] == operation and paused[0]['index'] == request and
                    paused[0]['phase'] == mode.removeprefix('pause-') and paused[0]['disk_sha256'] == interrupted
                    and not injected and failures == 0 and row['actual_vm_sigkill'] and
                    row['host_stopped_state'] in ('T', 't') and row['qmp_stop_requested'] and
                    not row['qmp_stop_acknowledged'] and row['paused_durable_bytes_unchanged_by_host_cleanup'],
                    'actual administration power cut or paused durable bytes differ')
        cases.append(dict(operation=operation, request=request, mode=mode))
    require(corpus.receipt['actual_vm_crashes'] == len(targets) * 2 and
            corpus.receipt['failed_fault_cells'] == 0, 'incomplete actual administration cut counts')
    require(corpus.archive(corpus.rows[-1]['retained_seed']) == prepare['host_state']['disk_sha256'],
            'prepared administration seed changed during the fault campaign')
    index = base_index([corpus])
    index.update(kind='fault', cache=cache, fault_modes=list(MODES),
                 physical_targets=[dict(operation=operation, request=request, labels=labels)
                                   for (operation, request), labels in targets.items()], cases=cases,
                 counts=dict(boots=1 + len(rows) * 2, faults=len(cases),
                             vm_kills=len(targets) * 2, device_errors=len(targets)))
    validate_index(index)
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    clean = sub.add_parser('collect-clean')
    clean.add_argument('--clean-directory', type=Path, required=True)
    clean.add_argument('--storage-directory', type=Path, required=True)
    fault = sub.add_parser('collect-fault')
    fault.add_argument('--directory', type=Path, required=True)
    matrix = sub.add_parser('verify')
    matrix.add_argument('--indices', type=Path, required=True)
    for command in (clean, fault, matrix):
        command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'choose a new administration evidence output')
    if args.operation == 'collect-clean':
        report = collect_clean(args.clean_directory, args.storage_directory)
    elif args.operation == 'collect-fault':
        report = collect_fault(args.directory)
    else:
        paths = sorted(args.indices.rglob('coverage-index.json'))
        indices = [json.loads(path.read_text()) for path in paths]
        report = verify_matrix(indices)
        for name, expected in indices[0]['source_inputs'].items():
            require(digest(ROOT / name) == expected, 'administration matrix source differs from this checkout')
        report['indices'] = {str(path): digest(path) for path in paths}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print('ACCOUNT_STORAGE_' + args.operation.upper() + '_PASS')


if __name__ == '__main__':
    main()

# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind rotation coverage to retained executions, then require the full shard union.

The runner performs the native filesystem/content checks. Collection verifies
their execution evidence and retained bytes; it never repairs or boots a disk.
"""
import argparse
import gzip
import hashlib
import itertools
import json
from pathlib import Path, PurePosixPath
import re

from account_storage_shards import partition_targets, verify_complete_shards

ROOT = Path(__file__).resolve().parents[1]
MODES = ('eio', 'pause-before', 'pause-after')
DIMENSIONS = (('build', 'runtime'), ('static', 'dynamic'), ('bios', 'uefi'),
              ('modern', 'legacy'), ('basic', 'expiry'), ('writeback', 'writethrough'))
PHASES = {'archive-created', 'archive-journal', 'archive-complete', 'marker',
          'carried-current', 'state-committed', 'marker-removed', 'trigger', 'projections'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def validate_index(index):
    require(index['format'] == 1 and index['retained_execution_verified'] is True,
            'not a collected rotation execution index')
    scope = index['scope']
    require(len(scope) == len(DIMENSIONS) and all(value in choices for value, choices in
                                                zip(scope, DIMENSIONS)), 'invalid rotation scope')
    require(index['guest_timeout_seconds'] == 90 and index['fault_modes'] == list(MODES),
            'rotation deadlines or fault modes differ')
    selection = index['target_selection']
    require(partition_targets(selection['all_targets'], selection['shard_index'],
                              selection['shard_count']) == selection, 'altered target selection')
    phases = {value['phase'] for value in selection['all_targets']}
    required = PHASES | ({'expiry-partial', 'expiry-complete'} if scope[4] == 'expiry' else set())
    require(required <= phases, 'missing required observed rotation phases')
    require({(value['phase'], value['operation']) for value in selection['all_targets']} ==
            set(itertools.product(phases, ('write', 'flush'))), 'missing write/flush target')
    expected = {'-'.join((target['phase'], target['operation'], str(target['request']), scope[5], mode))
                for target in selection['selected_targets'] for mode in MODES}
    require(len(index['cases']) == len(set(index['cases'])) and set(index['cases']) == expected,
            'missing, duplicate or unexpected rotation fault case')
    targets = len(selection['selected_targets'])
    require(index['counts'] == dict(faults=targets * 3, baselines=1, vm_kills=targets * 2,
                                    device_errors=targets, boots=targets * 6 + 2),
            'actual rotation execution counts differ from the selected grid')
    require(identity(index['source_inputs']) == index['source_identity'], 'altered source binding')
    require(index['evidence_files'] and all(re.fullmatch(r'[0-9a-f]{64}', value)
                                          for value in index['evidence_files'].values()),
            'missing retained execution bindings')
    return tuple(scope)


def verify_matrix(indices):
    require(bool(indices), 'no rotation storage indices')
    groups = {}
    sources = indices[0]['source_inputs']
    products = indices[0]['kernel_init_sha256']
    totals = dict(faults=0, baselines=0, vm_kills=0, device_errors=0, boots=0)
    for index in indices:
        scope = validate_index(index)
        require(index['source_inputs'] == sources and index['kernel_init_sha256'] == products,
                'rotation shards used different source or kernel/init inputs')
        groups.setdefault(scope, []).append(index['target_selection'])
        for name in totals:
            totals[name] += index['counts'][name]
    require(set(groups) == set(itertools.product(*DIMENSIONS)),
            'incomplete provider/linkage/firmware/transport/scenario/cache matrix')
    target_count = 0
    for selections in groups.values():
        target_count += verify_complete_shards(selections)['logical_targets']
    require(totals['faults'] == target_count * len(MODES), 'incomplete rotation fault-mode union')
    return dict(passed=True, matrix_complete=True, groups=len(groups), shards=len(indices),
                logical_targets=target_count, counts=totals, source_identity=identity(sources),
                kernel_init_sha256=products)


def collect(directory, source_root=ROOT):
    directory = directory.resolve()
    read = lambda path: json.loads(path.read_text())
    acceptance = read(directory / 'acceptance.json')
    require(all(acceptance[name] is True for name in
                ('passed', 'terminal', 'source_stable', 'journaled', 'frozen_products_unchanged')),
            'rotation producer is incomplete, failed or changed its inputs')
    require(not acceptance['wrapped'] and not acceptance['host_filesystem_repair'] and
            not acceptance['repaired_filesystems'], 'wrapped or host-repaired rotation result')
    selected = acceptance['selection']
    scope = [selected[name] for name in ('provider', 'linkage', 'firmware', 'transport')]
    for name in ('scenario', 'cache_model'):
        require(len(selected[name]) == 1, 'collect one scenario/cache per storage shard')
        scope.append(selected[name][0])
    require(all(value in choices for value, choices in zip(scope, DIMENSIONS)),
            'collect one provider/linkage/firmware/transport per storage shard')
    require(len(selected['fault_mode']) == len(MODES) and set(selected['fault_mode']) == set(MODES),
            'all three actual fault modes are required')
    remote = PurePosixPath(selected['directory'])
    require(remote.is_absolute() and '..' not in remote.parts, 'invalid producer directory')
    evidence = {}

    def bind(path, expected=None):
        require(path.is_file() and not path.is_symlink() and
                path.resolve().is_relative_to(directory), 'missing or escaped evidence file')
        actual = digest(path)
        require(expected is None or actual == expected, 'retained execution hash differs: ' + str(path))
        evidence[path.relative_to(directory).as_posix()] = actual
        return actual

    def local(value):
        path = PurePosixPath(value)
        require(path.is_absolute() and '..' not in path.parts and path.is_relative_to(remote),
                'archive path is outside its producer directory')
        return directory / path.relative_to(remote).as_posix()

    def archive(record):
        path = local(record['path'])
        bind(path, record['compressed']['sha256'])
        require(path.stat().st_size == record['compressed']['bytes'], 'compressed volume size differs')
        require(record['original']['bytes'] == 16 * 1024 * 1024, 'unexpected rotation volume size')
        with gzip.open(path, 'rb') as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        require(len(raw) == record['original']['bytes'] and
                hashlib.sha256(raw).hexdigest() == record['original']['sha256'],
                'retained volume does not reproduce the actual disk')
        return record['original']['sha256']

    def log(path, row, phase=None):
        bind(path, row['log_sha256'])
        require(not row['timed_out'] and 0 < row['elapsed_ns'] < 90_000_000_000,
                'guest exceeded its original deadline')
        command = row['command']
        require(command[:9] == ['qemu-system-x86_64', '-machine', 'pc', '-cpu', 'max',
                               '-m', '256M', '-nic', 'none'], 'guest execution shape differs')
        require(not any(value in command for value in ('-icount', '-accel', '-rtc')),
                'guest timing or execution mode differs')
        image = local(command[command.index('-cdrom') + 1])
        bind(image)
        require('virtio-blk-pci,drive=records,rerror=report,werror=report,' +
                ('disable-legacy=on' if scope[3] == 'modern' else 'disable-modern=on') in command,
                'block transport differs')
        text = path.read_text().replace('\r\n', '\n')
        require('Firmware: ' + scope[2].upper() in text, 'guest firmware evidence differs')
        require(not any(value in text for value in ('PANIC:', 'FAULT pid=', 'ACCOUNT_ROTATION_EXT2_FAIL')),
                'guest reported a failure')
        if phase:
            require(row['returncode'] == 1 and
                    len(re.findall(r'^ACCOUNT_ROTATION_EXT2_PASS phase=' + phase + r' [^\n]*\n',
                                   text, re.M)) == 1 and
                    text.splitlines().count('AXIOM64_TESTS_PASS') == 1 and
                    text.splitlines().count('AXIOM64_EXIT status=0') == 1,
                    'guest success record is missing or incomplete')
        return text

    def trace(path, expected):
        bind(path, expected)
        raw = path.read_bytes()
        require(raw and raw.endswith(b'\n') and len(raw) <= 64 * 1024 * 1024,
                'incomplete or oversized device trace')
        rows = [json.loads(line) for line in raw.splitlines()]
        for row in rows:
            if row['event'] == 'write_complete':
                payload = bytes.fromhex(row['payload_hex'])
                require(len(payload) == row['bytes'] and hashlib.sha256(payload).hexdigest() ==
                        row['payload_sha256'], 'actual write payload differs')
        return rows

    def prefix(events, operation, request):
        result = []
        for event in events:
            if event['event'] != 'request':
                continue
            result.append([event['operation'], event.get('offset'), event.get('bytes')])
            if event['operation'] == operation and event['index'] == request:
                return result
        raise ValueError('selected physical device request is absent')

    sources = read(directory / 'source-inputs.json')
    bind(directory / 'source-inputs.json')
    for name, expected in sources.items():
        value = PurePosixPath(name)
        require(not value.is_absolute() and '..' not in value.parts and '.local' not in value.parts,
                'invalid captured source path')
        require(digest(source_root / name) == expected, 'current source differs from the execution')
        bind(directory / 'source' / name, expected)
    for name in ('scripts/account_rotation_storage_coverage.py', 'scripts/account_storage_shards.py'):
        sources[name] = digest(source_root / name)
    products = read(directory / 'frozen-products.json')
    bind(directory / 'frozen-products.json')
    product_binding = {}
    for name in ('build/axiom64.elf', 'build/init'):
        matches = [expected for path, expected in products.items() if path.endswith('/' + name)]
        require(len(matches) == 1 and digest(source_root / name) == matches[0],
                'kernel/init differs from the executed input')
        product_binding[name] = matches[0]
    profile = directory / (scope[0] + '-' + scope[1])
    group = profile / '-'.join(scope[2:5])
    selection = read(group / 'target-selection.json')
    bind(group / 'target-selection.json')
    require(selection['shard_index'] == selected['shard_index'] and
            selection['shard_count'] == selected['shard_count'], 'shard selector differs')
    baseline = read(group / 'baseline/result.json')
    require(baseline['passed'] and baseline['fault_mode'] == 'observe' and
            baseline['target_selection'] == selection, 'baseline selection differs')
    observed = read(group / 'baseline/observed-phases.json')
    bind(group / 'baseline/observed-phases.json')
    require(observed == baseline['observed_phases'], 'captured baseline phases differ')
    targets = [dict(phase=phase, operation=operation, request=request)
               for phase, value in observed.items()
               for operation, request in (('write', value['last_write']), ('flush', value['flush']))]
    require(partition_targets(targets, selected['shard_index'], selected['shard_count']) == selection,
            'selected targets differ from complete baseline observations')
    baseline_trace = trace(group / 'baseline/block.jsonl', baseline['run']['trace_sha256'])
    fault_cases = {}
    for target in selection['selected_targets']:
        for mode in MODES:
            label = '-'.join((target['phase'], target['operation'], str(target['request']), scope[5], mode))
            fault_cases[label] = dict(target, mode=mode)
    directories = {'baseline': group / 'baseline', **{name: group / name for name in fault_cases}}
    require(set(directory.rglob('result.json')) == {path / 'result.json' for path in directories.values()},
            'missing, failed or unexpected actual rotation attempt')
    results = read(directory / 'results.json')
    bind(directory / 'results.json')
    require(len(results) == len(directories) and acceptance['cells'] == len(results),
            'producer omitted actual rotation attempts')
    expected_rows = []
    for label, folder in directories.items():
        row = read(folder / 'result.json')
        bind(folder / 'result.json')
        require(row['passed'] and not row['wrapped'] and row['case'] == label and
                row['firmware'] == scope[2] and row['transport'] == scope[3] and row['scenario'] == scope[4],
                'actual rotation attempt scope differs')
        expected_rows.append(row)
        mode = row['fault_mode']
        text = log(folder / 'guest.log', row['run'], None if mode.startswith('pause-') else 'run')
        events = trace(folder / 'block.jsonl', row['run']['trace_sha256'])
        require(len([event for event in events if event['event'] == 'armed']) == 1,
                'device trace has no unique actual arm point')
        interrupted = archive(row['retained_interrupted'])
        require(interrupted == row['interrupted_disk_sha256'] == row['actual_device_disk_sha256'],
                'interrupted actual disk bytes differ')
        armed = archive(row['retained_armed'])
        require(armed == next(event['disk_sha256'] for event in events if event['event'] == 'armed'),
                'armed disk differs from the actual device observation')
        if label != 'baseline':
            target = fault_cases[label]
            require(mode == target['mode'] and row['cache_model'] == scope[5] and
                    row['operation'] == target['operation'] and row['request'] == target['request'],
                    'fault target differs')
            require(prefix(events, row['operation'], row['request']) ==
                    prefix(baseline_trace, row['operation'], row['request']),
                    'actual physical request prefix differs from baseline')
        injected = [event for event in events if event['event'] == 'injected']
        completion = folder / 'virtio.trace'
        bind(completion, row.get('virtio_trace_sha256'))
        failures = len(re.findall(r'virtio_blk_req_complete .*?status 1\b', completion.read_text()))
        if mode == 'eio':
            require(len(injected) == failures == row['failed_virtio_completions'] == 1 and
                    injected[0]['operation'] == row['operation'] and injected[0]['index'] == row['request'] and
                    'ACCOUNT_ROTATION_EXT2_ATTEMPT result=-1 errno=5\n' in text,
                    'missing actual failed device completion')
        elif mode.startswith('pause-'):
            paused = [event for event in events if event['event'] == 'paused']
            require(len(paused) == 1 and paused[0] == row['actual_pause'] and not injected and
                    paused[0]['operation'] == row['operation'] and paused[0]['index'] == row['request'] and
                    paused[0]['phase'] == mode.removeprefix('pause-') and
                    paused[0]['disk_sha256'] == interrupted and row['run']['returncode'] == -9 and
                    row['host_stopped_state'] in ('T', 't') and row['qmp_stop_requested'] and
                    not row['qmp_stop_acknowledged'] and row['power_loss'],
                    'missing actual stopped-VM power cut or changed durable bytes')
        else:
            require(mode == 'observe' and not injected and failures == 0 and
                    'ACCOUNT_ROTATION_EXT2_ATTEMPT result=0 errno=0\n' in text,
                    'baseline did not execute the successful actual operation')
        log(folder / 'recovery/guest.log', row['recovery'], 'recover')
        final = archive(row['retained_final'])
        require(final == row['recovery']['actual_device_disk_sha256'], 'actual recovery disk differs')
        check = row['post_recovery_fsck']
        require(check['passed'] and not check['timed_out'] and check['returncode'] == 0 and
                check['command'][:3] == ['e2fsck', '-f', '-n'], 'strict native postcheck failed')
        check_log = folder / 'recovered-fsck.log'
        bind(check_log, check['log_sha256'])
        native = check_log.read_text()
        require(all('Pass ' + str(number) + ':' in native for number in range(1, 6)) and
                not re.search(r'count wrong|bitmap differences|Fix\?|Clear\?|still has errors|skipping journal recovery', native, re.I),
                'native postcheck was incomplete or found damage')
        bind(folder / 'metadata.json')
        exports = folder / 'exports'
        require(exports.is_dir(), 'native account-record exports are missing')
        for path in exports.rglob('*'):
            if path.is_file():
                bind(path)
    require(sorted(results, key=lambda value: value['case']) ==
            sorted(expected_rows, key=lambda value: value['case']), 'producer result index differs')
    count = len(fault_cases)
    require(acceptance['actual_vm_crashes'] == count * 2 // 3, 'producer omitted actual power cuts')
    bind(directory / 'acceptance.json')
    index = dict(format=1, retained_execution_verified=True, scope=scope,
                 guest_timeout_seconds=90, fault_modes=list(MODES), target_selection=selection,
                 cases=list(fault_cases), counts=dict(faults=count, baselines=1, vm_kills=count * 2 // 3,
                                                     device_errors=count // 3, boots=(count + 1) * 2),
                 source_inputs=sources, source_identity=identity(sources), kernel_init_sha256=product_binding,
                 evidence_files=dict(evidence))
    validate_index(index)
    require(all(digest(source_root / name) == expected for name, expected in sources.items()),
            'source changed during evidence collection')
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    one = sub.add_parser('collect', help='verify one completed provider/linkage/device/scenario/cache shard')
    one.add_argument('--directory', type=Path, required=True)
    one.add_argument('--output', type=Path, required=True)
    matrix = sub.add_parser('verify', help='require every variant, target, fault mode and shard')
    matrix.add_argument('--indices', type=Path, required=True)
    matrix.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'choose a new evidence output')
    if args.operation == 'collect':
        report = collect(args.directory)
    else:
        paths = sorted(args.indices.rglob('coverage-index.json'))
        indices = [json.loads(path.read_text()) for path in paths]
        report = verify_matrix(indices)
        for name, expected in indices[0]['source_inputs'].items():
            require(digest(ROOT / name) == expected, 'matrix source differs from this checkout')
        report['indices'] = {str(path): digest(path) for path in paths}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print('ROTATION_STORAGE_' + args.operation.upper() + '_PASS')


if __name__ == '__main__':
    main()

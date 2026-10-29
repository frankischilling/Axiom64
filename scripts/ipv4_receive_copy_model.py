# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind IPv4 result-copy ordering to an independent actual-kernel ABI probe."""
import hashlib
import json
from pathlib import Path
import re
import struct
import tempfile
import zipfile


def require(value, reason):
    if not value:
        raise ValueError(reason)


def parse_probe(text, release):
    require(text.splitlines().count('IPV4_COPY_MODEL_KERNEL release=' + release) == 1 and
            text.splitlines().count('IPV4_COPY_MODEL_DONE cases=4') == 1 and
            'IPV4_COPY_MODEL_FAIL' not in text, 'complete independent probe on the recorded kernel')
    rows = []
    for line in text.splitlines():
        if not line.startswith('IPV4_COPY_MODEL_CASE '):
            continue
        pairs = [part.split('=', 1) for part in line.split()[1:]]
        row = dict(pairs)
        require(len(pairs) == 6 and set(row) == {'mode', 'result', 'errno', 'length', 'payload', 'name'},
                'exact independent probe fields')
        require(all(re.fullmatch(r'-?\d+', row[key]) for key in row if key != 'name') and
                re.fullmatch('[0-9a-f]+', row['name']) is not None, 'original probe values')
        require(row['mode'] == str(len(rows)) and row['result'] == '-1' and row['errno'] == '14' and
                row['payload'] == '90', 'ordered actual post-payload EFAULT observations')
        rows.append(row)
    require(len(rows) == 4, 'both recvfrom and recvmsg source/length faults')
    source = struct.pack('<H', 2) + struct.pack('!H', 53598) + b'\x7f\0\0\1' + bytes(8)
    old = all(row['length'] == '40' and row['name'] ==
              ('02' if index in (0, 3) else (source + b'\xa5' * 24).hex())
              for index, row in enumerate(rows))
    new = all(row['length'] == ('16' if index in (0, 3) else '40') and row['name'] ==
              ('02' if index in (0, 3) else (b'\xa5' * 40).hex())
              for index, row in enumerate(rows))
    require(old != new, 'one observed source store order shared by recvfrom and recvmsg')
    return 'address-first' if old else 'length-first'


def load(directory, inputs):
    directory = Path(directory)
    record = json.loads((directory / 'native-copy-model.json').read_text())
    case = directory / 'native-copy-model'
    raw = (case / 'client.log').read_bytes()
    source = case / 'probe.c'
    program = case / 'program.elf'
    before_raw = (case / 'preexecution.json').read_bytes()
    before = json.loads(before_raw)
    source_inputs = (directory / 'source/source-inputs.json').read_bytes()
    require(record['preexecution_sha256'] == hashlib.sha256(before_raw).hexdigest() and
            before['source']['source_inputs_sha256'] == hashlib.sha256(source_inputs).hexdigest() and
            json.loads(source_inputs) == inputs and before['source']['source_zip_sha256'] ==
            hashlib.sha256((directory / 'source/source.zip').read_bytes()).hexdigest(),
            'original preexecution record and complete frozen source')
    require(record['source_sha256'] == inputs['userspace/tests/net/ipv4_copy_model.c'] ==
            hashlib.sha256(source.read_bytes()).hexdigest(), 'frozen independent probe source binding')
    require(record['program_sha256'] == hashlib.sha256(program.read_bytes()).hexdigest() and
            record['log_sha256'] == hashlib.sha256(raw).hexdigest(), 'original probe program and observations')
    require(record['program_sha256'] == before['program_sha256'] and
            record['source_sha256'] == before['source_sha256'] and record['kernel'] == before['kernel'] and
            record['command'] == before['command'] == json.loads((case / 'command.json').read_text()) and
            record['execution'] == json.loads((case / 'process.json').read_text()),
            'actual probe execution owns its original source, program and command')
    require(record['execution']['status'] == 'completed' and
            type(record['execution']['pid']) is int and record['execution']['pid'] > 0 and
            record['execution']['returncode'] == 0 and not record['execution']['timed_out'] and
            record['execution']['log_sha256'] == record['log_sha256'], 'successful actual independent probe')
    order = parse_probe(raw.decode(), record['kernel']['release'])
    require(record['kernel']['sysname'] == 'Linux' and record['order'] == order,
            'Linux model selected only by its original probe')
    return record


def damaged_controls(directory, inputs, archive):
    """Reopen serialized counterexamples without changing the original cohort."""
    directory, archive = Path(directory), Path(archive)
    load(directory, inputs)
    names = ['native-copy-model.json', 'source/source.zip', 'source/source-inputs.json',
             *('native-copy-model/' + name for name in ('preexecution.json', 'command.json',
                                                       'process.json', 'client.log', 'probe.c', 'program.elf'))]
    original = {name: (directory / name).read_bytes() for name in names}

    def model_change(change):
        record = json.loads(original['native-copy-model.json'])
        change(record)
        return {'native-copy-model.json': json.dumps(record).encode()}

    def execution_change(change):
        record = json.loads(original['native-copy-model.json'])
        change(record['execution'])
        return {'native-copy-model.json': json.dumps(record).encode(),
                'native-copy-model/process.json': json.dumps(record['execution']).encode()}

    def log_change(change):
        raw = change(original['native-copy-model/client.log'].decode()).encode()
        record = json.loads(original['native-copy-model.json'])
        record['log_sha256'] = record['execution']['log_sha256'] = hashlib.sha256(raw).hexdigest()
        return {'native-copy-model.json': json.dumps(record).encode(),
                'native-copy-model/process.json': json.dumps(record['execution']).encode(),
                'native-copy-model/client.log': raw}

    record = json.loads(original['native-copy-model.json'])
    opposite = 'length-first' if record['order'] == 'address-first' else 'address-first'
    cases = {
        'unobserved-order': model_change(lambda value: value.update(order=opposite)),
        'different-kernel': model_change(lambda value: value['kernel'].update(release='different-kernel')),
        'wrong-program-hash': model_change(lambda value: value.update(program_sha256='0' * 64)),
        'wrong-source-hash': model_change(lambda value: value.update(source_sha256='0' * 64)),
        'wrong-preexecution-hash': model_change(lambda value: value.update(preexecution_sha256='0' * 64)),
        'unfinished-process': execution_change(lambda value: value.update(status='running')),
        'failed-process': execution_change(lambda value: value.update(returncode=1)),
        'timed-out-process': execution_change(lambda value: value.update(timed_out=True)),
        'wrong-process-owner': {'native-copy-model/process.json': json.dumps(dict(record['execution'], pid=0)).encode()},
        'missing-probe-case': log_change(lambda text: '\n'.join(line for line in text.splitlines() if not line.startswith('IPV4_COPY_MODEL_CASE mode=3 ')) + '\n'),
        'duplicate-probe-case': log_change(lambda text: text.replace('mode=3 ', 'mode=2 ')),
        'uncopied-probe-payload': log_change(lambda text: text.replace('payload=90', 'payload=165', 1)),
        'altered-probe-address': log_change(lambda text: text.replace('name=02', 'name=03', 1)),
        'altered-source-snapshot': {'source/source.zip': original['source/source.zip'] + b'changed'},
    }
    changed_program = b'X' + original['native-copy-model/program.elf'][1:]
    cases['changed-program-and-claim'] = model_change(lambda value: value.update(
        program_sha256=hashlib.sha256(changed_program).hexdigest()))
    cases['changed-program-and-claim']['native-copy-model/program.elf'] = changed_program
    changed_source = original['native-copy-model/probe.c'] + b'\n/* changed */\n'
    cases['changed-source-and-claim'] = model_change(lambda value: value.update(
        source_sha256=hashlib.sha256(changed_source).hexdigest()))
    cases['changed-source-and-claim']['native-copy-model/probe.c'] = changed_source
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr('index.json', json.dumps({label: sorted(changes) for label, changes in cases.items()}))
        for label, changes in cases.items():
            for name, data in changes.items():
                bundle.writestr(label + '/' + name, data)
    rejected = []
    with tempfile.TemporaryDirectory(prefix='ipv4-copy-model-', dir=archive.parent) as temporary:
        stage = Path(temporary)
        for name, data in original.items():
            (stage / name).parent.mkdir(parents=True, exist_ok=True)
            (stage / name).write_bytes(data)
        load(stage, inputs)
        with zipfile.ZipFile(archive) as bundle:
            index = json.loads(bundle.read('index.json'))
            for label, changed_names in index.items():
                for name in changed_names:
                    (stage / name).write_bytes(bundle.read(label + '/' + name))
                try:
                    load(stage, inputs)
                except (ValueError, KeyError, TypeError):
                    rejected.append(label)
                else:
                    raise ValueError('altered independent copy model was accepted: ' + label)
                finally:
                    for name in changed_names:
                        (stage / name).write_bytes(original[name])
    require(all((directory / name).read_bytes() == data for name, data in original.items()),
            'independent probe and source originals remain unchanged')
    return rejected

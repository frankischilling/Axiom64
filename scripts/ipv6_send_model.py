# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind native traffic class and option-memory admission to an independent probe."""
import hashlib
import json
from pathlib import Path
import re
import struct


def require(value, message):
    if not value:
        raise ValueError(message)


def parse_probe(text, release):
    lines = text.splitlines()
    require(len(lines) == 13 and lines[0] == 'IPV6_SEND_MODEL_KERNEL release=' + release and
            lines[-1] == 'IPV6_SEND_MODEL_DONE cases=2 guards=8', 'exact ordered independent send probe records')
    require(text.splitlines().count('IPV6_SEND_MODEL_KERNEL release=' + release) == 1 and
            text.splitlines().count('IPV6_SEND_MODEL_DONE cases=2 guards=8') == 1 and
            'IPV6_SEND_MODEL_FAIL' not in text, 'complete independent send model on the recorded kernel')
    samples = []
    for line in text.splitlines():
        if not line.startswith('IPV6_SEND_MODEL_CASE '):
            continue
        pairs = [item.split('=', 1) for item in line.split()[1:]]
        row = dict(pairs)
        require(len(pairs) == 6 and set(row) == {'case', 'input', 'class', 'byte', 'sticky', 'control'},
                'exact independent send model fields')
        require(all(re.fullmatch(r'-?\d+', row[key]) for key in row if key != 'control') and
                re.fullmatch('[0-9a-f]{48}', row['control']) is not None, 'original send model bytes')
        at = len(samples)
        require(at < 2 and row['case'] == str(at) and row['input'] == ('170' if not at else '-1') and
                row['byte'] == '90' and row['sticky'] == '18', 'ordered actual datagrams and unchanged option')
        data = bytes.fromhex(row['control'])
        require(data[:16] == struct.pack('<Qii', 20, 41, 67) and data[20:] == b'\xa5' * 4 and
                int.from_bytes(data[16:20], 'little') == int(row['class']), 'complete received class and padding')
        samples.append(int(row['class']))
    require(len(samples) == 2 and samples[0] == 170 and samples[1] in (18, 255),
            'one recognized native minus-one class behavior')
    setting = re.fullmatch(r'IPV6_SEND_MODEL_OPTMEM max=(\d+)', lines[3])
    require(setting is not None, 'independent actual option-memory setting')
    limit = int(setting.group(1))
    require(1 < limit <= 2147483647, 'bounded option-memory setting')
    sizes = (1, limit - 1, limit, 65535, 65536, 131071, 131072, 2147483647)
    for at, size in enumerate(sizes):
        expected = f'IPV6_SEND_MODEL_GUARD case={at} size={size} result=-1 errno={105 if size >= limit else 14}'
        require(lines[4 + at] == expected, 'actual allocation boundary and protected input ordering')
    return dict(minus_one_class=samples[1], optmem_max=limit)


def load(directory):
    directory = Path(directory)
    proof = json.loads((directory / 'native-send-model.json').read_text())
    raw = (directory / 'native-send-model.log').read_bytes()
    before = json.loads((directory / 'preexecution.json').read_text())
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    require(proof['kernel'] == before['kernel'] and proof['probe_log_sha256'] == hashlib.sha256(raw).hexdigest(),
            'original native send model and kernel identity')
    require(proof['probe_program_sha256'] == digest(directory / 'products/send-model-native') and
            proof['probe_source_sha256'] == digest(directory / 'products/send-model.c') and
            proof['probe_program_sha256'] == before['product_sha256'][proof['probe_program']] and
            proof['probe_source_sha256'] == before['source_sha256']['userspace/tests/net/ipv6_send_model.c'],
            'preserved native send probe source and executable bindings')
    value = parse_probe(raw.decode(), before['kernel']['release'])
    require(all(proof[key] == value[key] for key in value), 'native send model agrees with its original probe')
    receipt = json.loads((directory / 'receipt.json').read_text())
    require(receipt['passed'] and receipt['source_products_unchanged'] and
            receipt['native_send_model_sha256'] == digest(directory / 'native-send-model.json'),
            'completed native execution binds the independent send model and unchanged inputs')
    return value


def target_rows(rows, minus_one_class, optmem_max=131072):
    require(minus_one_class in (18, 255), 'recognized native minus-one class behavior')
    require(1 < optmem_max <= 2147483647, 'bounded native option-memory setting')
    result = []
    for original in rows:
        row = dict(original)
        variant = int(row['variant'])
        if 81 <= variant <= 94:
            size = (1, 15, 16, 20, 88, 4096, 8192, 65535, 65536, 131071,
                    131072, 131073, 262144, 2147483647)[variant - 81]
            require(row['result'] == row['received'] == '-1' and
                    row['errno'] == str(105 if size >= optmem_max else 14) and
                    row['receive_errno'] == '11', 'original protected control follows probed memory admission')
            row['errno'] = str(105 if size >= 131072 else 14)
        if int(row['variant']) == 8:
            control = bytearray.fromhex(row['control'])
            require(row['result'] == row['received'] == '32' and row['errno'] == row['receive_errno'] == '0' and
                    row['class'] == '18' and row['hops'] == '33' and row['length'] == '88' and row['flags'] == '0' and
                    control[64:80] == struct.pack('<Qii', 20, 41, 67) and
                    int.from_bytes(control[80:84], 'little') == minus_one_class,
                    'native original minus-one control and unchanged socket policy')
            control[80:84] = (255).to_bytes(4, 'little')
            row['control'] = control.hex()
        result.append(row)
    return result

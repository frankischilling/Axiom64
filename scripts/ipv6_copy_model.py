# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep native source-address copy expectations bound to an independent ABI probe."""
import hashlib
import json
from pathlib import Path
import re
import struct

ORDERS=('address-first','length-first')


def require(value,message):
    if not value:
        raise ValueError(message)


def sockaddr(port):
    return struct.pack('<H',10)+struct.pack('!H',port)+bytes(4)+bytes(15)+b'\1'+bytes(4)


def parse_probe(text,release):
    require(text.splitlines().count('IPV6_COPY_MODEL_KERNEL release='+release)==1 and
            text.splitlines().count('IPV6_COPY_MODEL_DONE cases=2')==1 and
            'IPV6_COPY_MODEL_FAIL' not in text,'complete probe on the actual recorded kernel')
    samples=[]
    for line in text.splitlines():
        if line.startswith('IPV6_COPY_MODEL_CASE '):
            pairs=[item.split('=',1) for item in line.split()[1:]]
            row=dict(pairs)
            require(len(pairs)==6 and set(row)=={'mode','result','errno','length','payload','name'},
                    'exact independent copy probe fields')
            require(all(re.fullmatch(r'-?\d+',row[key]) for key in row if key!='name') and
                    re.fullmatch('[0-9a-f]+',row['name']) is not None,'original copy probe bytes')
            require(row['mode']==str(len(samples)) and row['result']=='-1' and row['errno']=='14' and
                    row['payload']=='90','actual fault, copied input and ordered probe cases')
            samples.append(row)
    require(len(samples)==2 and samples[0]['name']=='0a' and samples[1]['length']=='40',
            'complete independent address and length guards')
    old=samples[0]['length']=='40' and samples[1]['name']==(sockaddr(53570)+b'\xa5'*12).hex()
    new=samples[0]['length']=='28' and samples[1]['name']==(b'\xa5'*40).hex()
    require(old!=new,'one recognized source-address store order; unknown behavior is rejected')
    return 'address-first' if old else 'length-first'


def load(directory):
    directory=Path(directory)
    proof=json.loads((directory/'native-copy-model.json').read_text())
    raw=(directory/'native-copy-model.log').read_bytes()
    before=json.loads((directory/'preexecution.json').read_text())
    require(proof['kernel']==before['kernel'] and
            proof['probe_log_sha256']==hashlib.sha256(raw).hexdigest(),
            'original independent probe and kernel identity')
    require(proof['probe_program_sha256']==hashlib.sha256((directory/'products/copy-model-native').read_bytes()).hexdigest() and
            proof['probe_source_sha256']==hashlib.sha256((directory/'products/copy-model.c').read_bytes()).hexdigest(),
            'preserved actual independent probe source and executable')
    receipt_path=directory/'receipt.json'
    if receipt_path.is_file():
        receipt=json.loads(receipt_path.read_text())
        require(receipt['native_copy_model_sha256']==hashlib.sha256((directory/'native-copy-model.json').read_bytes()).hexdigest(),
                'native execution receipt binds the independent model record')
    order=parse_probe(raw.decode(),before['kernel']['release'])
    require(proof['source_order']==order and
            proof['probe_program_sha256']==before['product_sha256'][proof['probe_program']] and
            proof['probe_source_sha256']==before['source_sha256']['userspace/tests/net/ipv6_copy_model.c'],
            'exact native probe source, product and result bindings')
    return order


def order(value):
    require(value in ORDERS,'explicit recognized native source-address order')
    return value


def canonical_faults(rows,native_order):
    order(native_order)
    result=[]
    for original in rows:
        row=dict(original)
        mode,prefix=int(row['length_mode']),int(row['prefix'])
        source=sockaddr(0 if int(row['kind']) else 53567)
        if not mode and prefix<28:
            require(row['result']=='-1' and row['errno']=='14' and
                    row['name_length']==('40' if native_order=='address-first' else '28'),
                    'native address-fault length follows its independent model')
            # Every visible source byte is checked before applying target rules.
            require(row['name']==source[:prefix].hex(),'native partial source address bytes')
            row['name_length']='28'
        if mode in (1,2):
            expected=(source+b'\xa5'*12)[:prefix] if native_order=='address-first' else b'\xa5'*prefix
            require(row['result']=='-1' and row['errno']=='14' and row['name_length']=='40' and
                    row['name']==expected.hex(),'native protected length preserves its exact address side effects')
            row['name']=(b'\xa5'*prefix).hex()
        result.append(row)
    return result


def canonical_headers(rows,native_order):
    order(native_order)
    result=[]
    for original in rows:
        row=dict(original)
        if int(row['mode'])==0 and int(row['prefix'])<12:
            source=sockaddr(0 if int(row['kind']) else 53568)
            expected=source+b'\xa5'*12 if native_order=='address-first' else b'\xa5'*40
            require(row['result']=='-1' and row['errno']=='14' and row['name_length']=='40' and
                    int.from_bytes(bytes.fromhex(row['header'])[8:12],'little')==40 and
                    row['name']==expected.hex(),
                    'native protected header length follows its independent model')
            row['name']=(b'\xa5'*40).hex()
        result.append(row)
    return result


def canonical_errors(rows,native_order):
    order(native_order)
    result=[]
    source=sockaddr(59999)
    for original in rows:
        row=dict(original)
        mode,prefix=int(row['mode']),int(row['prefix'])
        if mode==2 and prefix<28:
            expected='40' if native_order=='address-first' else '28'
            require(row['result']=='-1' and row['errno']=='14' and row['name_length']==expected and
                    int.from_bytes(bytes.fromhex(row['header'])[8:12],'little')==int(expected) and
                    row['name_prefix']==source[:prefix].hex(),
                    'native error source fault follows its independent model')
            header=bytearray.fromhex(row['header']);header[8:12]=(28).to_bytes(4,'little')
            row['header']=header.hex();row['name_length']='28'
        if (mode==3 and prefix<12) or mode==7:
            expected=source+b'\xa5'*12 if native_order=='address-first' else b'\xa5'*40
            require(row['result']=='-1' and row['errno']=='14' and row['name']==expected.hex(),
                    'native error protected length preserves its exact address effects')
            row['name']=(b'\xa5'*40).hex()
        if mode==10:
            expected=source[:1] if native_order=='address-first' else b'\xa5'
            require(row['result']=='-1' and row['errno']=='14' and row['name_prefix']==expected.hex(),
                    'native error protected recvfrom length preserves its address prefix')
            row['name_prefix']='a5'
        result.append(row)
    return result

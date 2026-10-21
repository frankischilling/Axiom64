# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject wrong source-copy models and altered native fault evidence."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ipv6_copy_model import canonical_errors, canonical_faults, canonical_headers, load, parse_probe

SOURCE=bytes.fromhex('0a00d142000000000000000000000000000000000000000100000000')


def probe(legacy):
    return ('IPV6_COPY_MODEL_KERNEL release=6.17-fixture\n'
            'IPV6_COPY_MODEL_CASE mode=0 result=-1 errno=14 length='+('40' if legacy else '28')+
            ' payload=90 name=0a\nIPV6_COPY_MODEL_CASE mode=1 result=-1 errno=14 length=40 payload=90 name='+
            ((SOURCE+b'\xa5'*12) if legacy else b'\xa5'*40).hex()+
            '\nIPV6_COPY_MODEL_DONE cases=2\n')


class CopyModels(unittest.TestCase):
    def test_independent_probe_recognizes_both_orders(self):
        self.assertEqual(parse_probe(probe(True),'6.17-fixture'),'address-first')
        self.assertEqual(parse_probe(probe(False),'6.17-fixture'),'length-first')

    def test_mixed_behavior_is_not_an_accepted_model(self):
        with self.assertRaises(ValueError):
            parse_probe(probe(False).replace('length=28','length=40'),'6.17-fixture')

    def test_probe_kernel_must_match(self):
        with self.assertRaises(ValueError):
            parse_probe(probe(True),'7.0-fixture')

    def test_changed_probe_payload_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_probe(probe(True).replace('payload=90','payload=91'),'6.17-fixture')

    def test_repaired_digest_cannot_hide_wrong_probe_address(self):
        with self.assertRaises(ValueError):
            parse_probe(probe(True).replace('name=0a\n','name=ff\n'),'6.17-fixture')

    def test_address_fault_checks_original_bytes_before_target_expectations(self):
        row=dict(kind='0',length_mode='0',prefix='1',result='-1',errno='14',name_length='40',name='0a')
        original=copy.deepcopy(row)
        self.assertEqual(canonical_faults([row],'address-first')[0]['name_length'],'28')
        self.assertEqual(row,original)
        row['name']='a5'
        with self.assertRaises(ValueError):canonical_faults([row],'address-first')

    def test_wrong_legacy_fault_length_is_rejected(self):
        row=dict(kind='0',length_mode='0',prefix='1',result='-1',errno='14',name_length='28',name='0a')
        with self.assertRaises(ValueError):canonical_faults([row],'address-first')

    def test_modern_protected_length_must_not_write_an_address(self):
        row=dict(kind='0',length_mode='1',prefix='40',result='-1',errno='14',name_length='40',
                 name=(bytes.fromhex('0a00d13f000000000000000000000000000000000000000100000000')+b'\xa5'*12).hex())
        with self.assertRaises(ValueError):canonical_faults([row],'length-first')

    def test_legacy_header_source_padding_is_checked(self):
        header=bytearray(b'\xa5'*56);header[8:12]=(40).to_bytes(4,'little')
        name=bytes.fromhex('0a00d140000000000000000000000000000000000000000100000000')+b'\xa5'*12
        row=dict(kind='0',mode='0',prefix='11',result='-1',errno='14',name_length='40',header=header.hex(),name=name.hex())
        self.assertEqual(canonical_headers([row],'address-first')[0]['name'],(b'\xa5'*40).hex())
        row['name']=(name[:-1]+b'\0').hex()
        with self.assertRaises(ValueError):canonical_headers([row],'address-first')

    def test_error_source_fault_checks_original_header_and_prefix(self):
        header=bytearray(b'\xa5'*56);header[8:12]=(40).to_bytes(4,'little')
        row=dict(mode='2',prefix='1',result='-1',errno='14',name_length='40',header=header.hex(),name_prefix='0a')
        result=canonical_errors([row],'address-first')[0]
        self.assertEqual(result['name_length'],'28')
        self.assertEqual(int.from_bytes(bytes.fromhex(result['header'])[8:12],'little'),28)
        row['name_prefix']='00'
        with self.assertRaises(ValueError):canonical_errors([row],'address-first')

    def test_error_readonly_length_does_not_discard_wrong_legacy_address(self):
        row=dict(mode='7',prefix='0',result='-1',errno='14',name=(b'\xa5'*40).hex())
        with self.assertRaises(ValueError):canonical_errors([row],'address-first')

    def test_unknown_order_is_rejected(self):
        with self.assertRaises(ValueError):canonical_faults([],'unknown')

    def test_preserved_native_program_is_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);(directory/'products').mkdir()
            program=b'independent executable fixture';source=b'independent source fixture'
            (directory/'products/copy-model-native').write_bytes(program)
            (directory/'products/copy-model.c').write_bytes(source)
            raw=probe(True).encode();(directory/'native-copy-model.log').write_bytes(raw)
            digest=lambda value:hashlib.sha256(value).hexdigest()
            kernel={'release':'6.17-fixture'}
            before=dict(kernel=kernel,product_sha256={'/probe':digest(program)},
                        source_sha256={'userspace/tests/net/ipv6_copy_model.c':digest(source)})
            model=dict(kernel=kernel,source_order='address-first',probe_log_sha256=digest(raw),
                       probe_program='/probe',probe_program_sha256=digest(program),probe_source_sha256=digest(source))
            (directory/'preexecution.json').write_text(json.dumps(before))
            (directory/'native-copy-model.json').write_text(json.dumps(model))
            self.assertEqual(load(directory),'address-first')
            (directory/'products/copy-model-native').write_bytes(b'changed')
            with self.assertRaises(ValueError):load(directory)


if __name__=='__main__':
    unittest.main(verbosity=2)

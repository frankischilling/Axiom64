# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject unbound traffic-class models and changes hidden by adaptation."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ipv6_send_model import load, parse_probe, target_rows


def digest(value):
    return hashlib.sha256(value).hexdigest()


def probe(value, limit=131072):
    lines = ['IPV6_SEND_MODEL_KERNEL release=fixture']
    for at, actual in enumerate((170, value)):
        control = struct.pack('<Qiii', 20, 41, 67, actual) + b'\xa5' * 4
        lines.append(f'IPV6_SEND_MODEL_CASE case={at} input={170 if not at else -1} '
                     f'class={actual} byte=90 sticky=18 control={control.hex()}')
    lines.append(f'IPV6_SEND_MODEL_OPTMEM max={limit}')
    for at, size in enumerate((1, limit - 1, limit, 65535, 65536, 131071, 131072, 2147483647)):
        lines.append(f'IPV6_SEND_MODEL_GUARD case={at} size={size} result=-1 errno={105 if size >= limit else 14}')
    return '\n'.join([*lines, 'IPV6_SEND_MODEL_DONE cases=2 guards=8', ''])


def sample(value):
    control = bytearray(b'\xa5' * 192)
    control[64:84] = struct.pack('<Qiii', 20, 41, 67, value)
    return dict(variant='8', result='32', received='32', errno='0', receive_errno='0',
                length='88', flags='0', hops='33', **{'class': '18'}, control=control.hex())


def saved_model(directory, value=18):
    products = directory / 'products'
    products.mkdir()
    program, source, raw = b'probe program fixture', b'probe source fixture', probe(value).encode()
    (products / 'send-model-native').write_bytes(program)
    (products / 'send-model.c').write_bytes(source)
    (directory / 'native-send-model.log').write_bytes(raw)
    kernel = dict(release='fixture')
    before = dict(kernel=kernel, product_sha256={'/probe': digest(program)},
                  source_sha256={'userspace/tests/net/ipv6_send_model.c': digest(source)})
    model = dict(kernel=kernel, minus_one_class=value, optmem_max=131072, probe_log_sha256=digest(raw),
                 probe_program='/probe', probe_program_sha256=digest(program),
                 probe_source_sha256=digest(source))
    (directory / 'preexecution.json').write_text(json.dumps(before))
    (directory / 'native-send-model.json').write_text(json.dumps(model))
    receipt = dict(passed=True, source_products_unchanged=True,
                   native_send_model_sha256=digest((directory / 'native-send-model.json').read_bytes()))
    (directory / 'receipt.json').write_text(json.dumps(receipt))


class SendModels(unittest.TestCase):
    def test_recognizes_both_actual_class_models(self):
        for value in (18, 255):
            for limit in (20480, 131072):
                self.assertEqual(parse_probe(probe(value, limit), 'fixture'),
                                 dict(minus_one_class=value, optmem_max=limit))

    def test_rejects_unknown_or_changed_probe_observations(self):
        changes = [('class=18 ', 'class=19 '), ('class=170 ', 'class=18 '),
                   ('byte=90', 'byte=91'), ('sticky=18', 'sticky=19'),
                   ('a5a5a5a5', 'a5a5a500'), ('input=-1', 'input=0'),
                   ('case=1', 'case=0')]
        for old, new in changes:
            with self.subTest(change=(old, new)), self.assertRaises(ValueError):
                parse_probe(probe(18).replace(old, new), 'fixture')

    def test_kernel_and_record_order_are_exact(self):
        for text, kernel in ((probe(18), 'other'), ('extra\n' + probe(18), 'fixture'),
                             ('\n'.join(reversed(probe(18).splitlines())), 'fixture')):
            with self.subTest(text=text, kernel=kernel), self.assertRaises(ValueError):
                parse_probe(text, kernel)

    def test_only_independently_validated_class_bytes_change(self):
        original = sample(18)
        retained = copy.deepcopy(original)
        result = target_rows([original], 18)[0]
        expected = bytearray.fromhex(original['control'])
        expected[80:84] = (255).to_bytes(4, 'little')
        self.assertEqual(result, dict(original, control=expected.hex()))
        self.assertEqual(original, retained)
        self.assertEqual(target_rows([sample(255)], 255), [sample(255)])

    def test_wrong_model_or_shared_option_is_rejected_before_adaptation(self):
        for changed in (sample(255), dict(sample(18), **{'class': '19'}),
                        dict(sample(18), received='31'), dict(sample(18), flags='1')):
            with self.subTest(row=changed), self.assertRaises(ValueError):
                target_rows([changed], 18)
        with self.assertRaises(ValueError):
            target_rows([], 0)

    def test_other_variants_keep_every_original_byte(self):
        row = dict(sample(18), variant='9')
        self.assertEqual(target_rows([row], 255), [row])

    def test_allocation_boundary_must_agree_with_actual_guard_results(self):
        for altered in (probe(18, 20480).replace('max=20480', 'max=131072'),
                        probe(18, 20480).replace('size=20480 result=-1 errno=105',
                                                 'size=20480 result=-1 errno=14')):
            with self.subTest(text=altered), self.assertRaises(ValueError):
                parse_probe(altered, 'fixture')

    def test_original_memory_admission_is_checked_before_target_errno(self):
        row = dict(sample(18), variant='88', result='-1', received='-1', errno='105', receive_errno='11')
        original = copy.deepcopy(row)
        result = target_rows([row], 18, 20480)[0]
        self.assertEqual(result, dict(row, errno='14'))
        self.assertEqual(row, original)
        with self.assertRaises(ValueError):
            target_rows([dict(row, errno='14')], 18, 20480)
        with self.assertRaises(ValueError):
            target_rows([row], 18, 0)

    def test_preserved_program_source_log_and_receipt_are_bound(self):
        for name in ('products/send-model-native', 'products/send-model.c',
                     'native-send-model.log', 'native-send-model.json'):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                saved_model(directory)
                self.assertEqual(load(directory), dict(minus_one_class=18, optmem_max=131072))
                path = directory / name
                path.write_bytes(path.read_bytes() + b' ')
                with self.assertRaises((ValueError, KeyError)):
                    load(directory)

    def test_changed_preexecution_and_failed_completion_are_rejected(self):
        for name, field, value in (('preexecution.json', 'kernel', {'release': 'other'}),
                                   ('preexecution.json', 'product_sha256', {'/probe': '0' * 64}),
                                   ('preexecution.json', 'source_sha256',
                                    {'userspace/tests/net/ipv6_send_model.c': '0' * 64}),
                                   ('receipt.json', 'passed', False),
                                   ('receipt.json', 'source_products_unchanged', False),
                                   ('receipt.json', 'native_send_model_sha256', '0' * 64)):
            with self.subTest(name=name, field=field), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                saved_model(directory)
                path = directory / name
                record = json.loads(path.read_text())
                record[field] = value
                path.write_text(json.dumps(record))
                with self.assertRaises(ValueError):
                    load(directory)


if __name__ == '__main__':
    unittest.main(verbosity=2)

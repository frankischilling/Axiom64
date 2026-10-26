# SPDX-License-Identifier: GPL-3.0-or-later
"""Own one trace instance and retain original Linux timer/workqueue observations."""
import hashlib
import gzip
import json
import os
from pathlib import Path
import platform
import re
import struct
import time


def btf_structure(data, wanted):
    magic, version, flags, header, type_offset, type_length, strings_offset, strings_length = struct.unpack_from('<HBB5I', data)
    assert magic == 0xeb9f and version == 1 and flags == 0 and header >= 24
    begin, end = header + type_offset, header + type_offset + type_length
    strings = data[header + strings_offset:header + strings_offset + strings_length]
    assert end <= len(data) and len(strings) == strings_length and strings[:1] == b'\0'

    def name(offset):
        assert 0 <= offset < len(strings)
        limit = strings.index(b'\0', offset)
        return strings[offset:limit].decode()

    at = begin
    while at < end:
        offset, info, size = struct.unpack_from('<III', data, at)
        kind, count, bitfields = (info >> 24) & 31, info & 0xffff, bool(info >> 31)
        lengths = {1:4, 2:0, 3:12, 4:12*count, 5:12*count, 6:8*count,
                   7:0, 8:0, 9:0, 10:0, 11:0, 12:0, 13:8*count, 14:4,
                   15:12*count, 16:0, 17:4, 18:0, 19:12*count}
        assert kind in lengths and at + 12 + lengths[kind] <= end
        if kind == 4 and name(offset) == wanted:
            members = {}
            for index in range(count):
                member_name, member_type, bits = struct.unpack_from('<III', data, at + 12 + index*12)
                bit_offset = bits & 0xffffff if bitfields else bits
                members[name(member_name)] = dict(type=member_type, bit_offset=bit_offset)
            return dict(name=wanted, bytes=size, members=members)
        at += 12 + lengths[kind]
    raise ValueError('live kernel BTF structure missing: ' + wanted)


class TimerTrace:
    def __init__(self, output):
        self.output = Path(output)
        self.output.mkdir(exist_ok=False)
        self.parent = Path('/sys/kernel/tracing')
        self.instance = None
        self.closed = False
        self.receipt = dict(kernel=platform.uname()._asdict(), original_clocks_unchanged=True,
                            clock='mono', events=[], segments=[], setup_complete=False, cleanup_complete=False)
        self.original = {name:(self.parent/name).read_text() for name in
                         ('tracing_on', 'current_tracer', 'trace_clock', 'trace_options')}
        try:
            self.setup()
        except BaseException:
            self.close()
            raise

    def setup(self):
        symbols = {}
        for line in Path('/proc/kallsyms').read_text().splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[2] in ('addrconf_dad_work', 'delayed_work_timer_fn'):
                symbols[fields[2]] = int(fields[0], 16)
        assert set(symbols) == {'addrconf_dad_work', 'delayed_work_timer_fn'} and all(symbols.values())
        self.receipt['symbols'] = symbols
        btf = Path('/sys/kernel/btf/vmlinux').read_bytes()
        (self.output/'kernel-btf.bin').write_bytes(btf)
        self.receipt['btf_sha256'] = hashlib.sha256(btf).hexdigest()
        self.receipt['delayed_work'] = btf_structure(btf, 'delayed_work')
        path = Path('/boot/config-' + platform.release())
        config = path.read_bytes() if path.exists() else gzip.decompress(Path('/proc/config.gz').read_bytes())
        (self.output/'kernel-config').write_bytes(config)
        match = re.search(rb'^CONFIG_HZ=(\d+)$', config, re.MULTILINE)
        assert match
        self.receipt['HZ'] = int(match[1])
        name = f'axiom64-device-timers-{os.getpid()}'
        instance = self.parent/'instances'/name
        instance.mkdir()
        self.instance = instance
        assert self.instance.parent.resolve() == (self.parent/'instances').resolve()
        self.receipt['instance'] = name
        (instance/'tracing_on').write_text('0')
        (instance/'current_tracer').write_text('nop')
        (instance/'buffer_size_kb').write_text('4096')
        (instance/'trace_clock').write_text('mono')
        (instance/'options/hash-ptr').write_text('0')
        (instance/'options/overwrite').write_text('0')
        assert '[mono]' in (instance/'trace_clock').read_text()
        assert (instance/'options/hash-ptr').read_text().strip() == '0'
        for group, event, symbol in (
            ('timer', 'timer_start', 'delayed_work_timer_fn'),
            ('timer', 'timer_expire_entry', 'delayed_work_timer_fn'),
            ('workqueue', 'workqueue_queue_work', 'addrconf_dad_work'),
            ('workqueue', 'workqueue_execute_start', 'addrconf_dad_work'),
            ('workqueue', 'workqueue_execute_end', 'addrconf_dad_work')):
            path = instance/'events'/group/event
            saved = self.output/f'{event}.format'
            saved.write_text((path/'format').read_text())
            if event == 'timer_start' and platform.release() == '6.17.0-1022-azure':
                assert 'bucket_expiry' in saved.read_text()
            expression = f'function == 0x{symbols[symbol]:x}'
            (path/'filter').write_text(expression)
            actual = (path/'filter').read_text().strip()
            assert actual == expression
            (path/'enable').write_text('1')
            assert (path/'enable').read_text().strip() == '1'
            self.receipt['events'].append(dict(group=group, event=event, filter=actual))
        self.receipt['begin_monotonic_ns'] = time.monotonic_ns()
        (instance/'tracing_on').write_text('1')
        self.receipt['setup_complete'] = True

    def mark(self, label):
        assert self.instance and not self.closed and re.fullmatch(r'[A-Z0-9_ =-]+', label)
        stamp = time.monotonic_ns()
        (self.instance/'trace_marker').write_text(f'AXIOM64_DEVICE {label} monotonic_ns={stamp}')

    def save_segment(self, label):
        assert self.instance and re.fullmatch(r'[a-z0-9-]+', label)
        trace = (self.instance/'trace').read_bytes()
        path = self.output/(label+'.trace')
        assert not path.exists()
        path.write_bytes(trace)
        statistics = {}
        for source in sorted((self.instance/'per_cpu').glob('cpu*/stats')):
            text = source.read_text()
            (self.output/(label+'-'+source.parent.name+'.stats')).write_text(text)
            row = {key.strip():value.strip() for key,value in
                   (line.split(':',1) for line in text.splitlines() if ':' in line)}
            for key in ('overrun','commit overrun','dropped events'):
                assert int(row[key]) == 0, (source, key, row[key])
            statistics[source.parent.name] = row
        record = dict(path=path.name, sha256=hashlib.sha256(trace).hexdigest(), statistics=statistics)
        self.receipt['segments'].append(record)
        return record

    def drain(self, label):
        assert not self.closed
        (self.instance/'tracing_on').write_text('0')
        self.save_segment(label)
        (self.instance/'trace').write_text('')
        (self.instance/'tracing_on').write_text('1')

    def close(self):
        if self.closed:
            return
        self.closed = True
        errors = []
        try:
            if self.instance:
                (self.instance/'tracing_on').write_text('0')
                self.receipt['end_monotonic_ns'] = time.monotonic_ns()
                self.save_segment('final')
        except BaseException as error:
            errors.append(type(error).__name__ + ': ' + str(error))
        finally:
            if self.instance:
                try:
                    for event in self.receipt['events']:
                        (self.instance/'events'/event['group']/event['event']/'enable').write_text('0')
                    self.instance.rmdir()
                    assert not self.instance.exists()
                    self.receipt['cleanup_complete'] = True
                except BaseException as error:
                    errors.append('instance retirement: ' + type(error).__name__ + ': ' + str(error))
            for name, original in self.original.items():
                if (self.parent/name).read_text() != original:
                    errors.append('parent tracer changed: ' + name)
            self.receipt['errors'] = errors
            (self.output/'receipt.json').write_text(json.dumps(self.receipt,indent=2)+'\n')
        if errors:
            raise RuntimeError('; '.join(errors))

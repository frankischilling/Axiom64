# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep host interfaces unchanged while checking finite address expiry bins."""
import json
import os
import subprocess
import time

SECOND = 1_000_000_000
FOREVER = 0xffffffff
LIFETIMES = {'valid_life_time', 'preferred_life_time'}


def capture():
    began = time.monotonic_ns()
    raw = subprocess.check_output(['ip', '-json', 'address', 'show'])
    ended = time.monotonic_ns()
    return dict(begin_ns=began, end_ns=ended, namespace=os.readlink('/proc/self/ns/net'),
                interfaces=json.loads(raw))


def verify(before, after):
    if before['namespace'] != after['namespace']:
        raise ValueError('host network namespace changed')
    clocks = [before['begin_ns'], before['end_ns'], after['begin_ns'], after['end_ns']]
    if any(type(value) is not int or value < 0 for value in clocks) or clocks != sorted(clocks):
        raise ValueError('host network observation clocks are unordered')
    checked = []

    def lifetime(old, new, path):
        if old == new and old == 'forever':
            return
        if type(old) is not int or type(new) is not int or not (0 <= new <= old <= FOREVER):
            raise ValueError('host address lifetime changed: ' + path)
        if old == FOREVER:
            if new != old:
                raise ValueError('host permanent address lifetime changed: ' + path)
            return
        if not old and not new:
            return
        # Linux exports whole seconds. Each sample bounds the same expiry
        # within its one-second bin and actual command-observation interval.
        first = (before['begin_ns'] + (old - 1) * SECOND, before['end_ns'] + old * SECOND)
        second = (after['begin_ns'] + (new - 1) * SECOND, after['end_ns'] + new * SECOND)
        if max(first[0], second[0]) > min(first[1], second[1]):
            raise ValueError('host finite address expiry changed: ' + path)
        checked.append(dict(path=path, before=old, after=new, first_bin=first, second_bin=second))

    def compare(old, new, path='interfaces'):
        if type(old) is not type(new):
            raise ValueError('host interface value type changed: ' + path)
        if isinstance(old, dict):
            if old.keys() != new.keys():
                raise ValueError('host interface fields changed: ' + path)
            for key in old:
                child = path + '.' + key
                if key in LIFETIMES:
                    lifetime(old[key], new[key], child)
                else:
                    compare(old[key], new[key], child)
        elif isinstance(old, list):
            if len(old) != len(new):
                raise ValueError('host interface inventory changed: ' + path)
            for index, (left, right) in enumerate(zip(old, new)):
                compare(left, right, path + '[' + str(index) + ']')
        elif old != new:
            raise ValueError('host interface configuration changed: ' + path)

    compare(before['interfaces'], after['interfaces'])
    return dict(passed=True, interfaces_unchanged=True, finite_expiry_bins_checked=checked,
                before_begin_ns=before['begin_ns'], after_end_ns=after['end_ns'])

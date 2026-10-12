# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate captured UTC calendars and independently measured RTC progress."""
from datetime import datetime, timezone


def calendar(value):
    return int(datetime(value['tm_year']+1900, value['tm_mon']+1, value['tm_mday'],
                        value['tm_hour'], value['tm_min'], value['tm_sec'],
                        tzinfo=timezone.utc).timestamp())


def check_hardware(row, before, expected_date, events):
    sample_before, sample_after = row['hardware_interval_ns']
    actual = calendar(row['hardware_calendar'])*1_000_000_000
    base = sample_before if expected_date is None else int(datetime.fromisoformat(expected_date).replace(
           tzinfo=timezone.utc).timestamp())*1_000_000_000
    maximum = sample_after if expected_date is None else base+sample_after-before
    changes = [event for event in events if event.get('event') == 'RTC_CHANGE']
    row['hardware_firmware_changes'] = changes
    if expected_date is None:
        initial_before, initial_after = row.get('initial_hardware_interval_ns', [before, before])
        initial = calendar(row['initial_hardware_calendar'])*1_000_000_000
        if not before-1_000_000_000 <= initial <= initial_after+2_000_000_000:
            raise RuntimeError('the initial QEMU RTC differs from the observed current UTC')
        # Firmware rewrites whole RTC seconds during initialization. QEMU reports
        # each new calendar's offset from host UTC; use that independent input
        # rather than assuming the firmware preserved a zero offset.
        for event in changes:
            data, stamp = event['data'], event['timestamp']
            offset = data['offset']
            if (type(offset) is not int or not data['qom-path'].endswith('/rtc') or
                    type(stamp['seconds']) is not int or type(stamp['microseconds']) is not int or
                    not 0 <= stamp['microseconds'] < 1_000_000):
                raise RuntimeError('the recorded RTC firmware change is malformed')
            when = stamp['seconds']*1_000_000_000+stamp['microseconds']*1000
            written = (stamp['seconds']+offset)*1_000_000_000
            if (not before <= when <= sample_after or
                    not before-1_000_000_000 <= written <= when+2_000_000_000):
                raise RuntimeError('the recorded RTC firmware change is outside the observed boot')
    reference = row.get('reference_hardware_calendar', row['initial_hardware_calendar'])
    reference_before, reference_after = row.get('reference_hardware_monotonic_interval_ns',
                                                row['initial_hardware_monotonic_interval_ns'])
    observed_before, observed_after = row['hardware_monotonic_interval_ns']
    initial = calendar(reference)*1_000_000_000
    # clock=rt uses host monotonic time. RTC reads expose only whole seconds;
    # the observed reference's unknown fraction occupies exactly one second.
    progress_minimum = initial+observed_before-reference_after
    progress_maximum = initial+1_000_000_000+observed_after-reference_before
    if (not reference_before <= reference_after <= observed_before <= observed_after or
            not progress_minimum-1_000_000_000 <= actual <= progress_maximum+2_000_000_000):
        raise RuntimeError('the actual QEMU RTC differs from independently measured monotonic progress')
    if 'reference_firmware_changes' in row and changes != row['reference_firmware_changes']:
        raise RuntimeError('the RTC changed after the post-firmware hardware reference')
    row['hardware_progress_reference_ns'] = [progress_minimum, progress_maximum]
    if expected_date is None:
        base, maximum = progress_minimum, progress_maximum
    row['hardware_reference_ns'] = [base, maximum]
    if not base-1_000_000_000 <= actual <= maximum+2_000_000_000:
        raise RuntimeError('the actual QEMU RTC differs from the firmware calendar expectation')
    observed = row['observed']['seconds']*1_000_000_000 + row['observed']['nanoseconds']
    if not -1_000_000_000 <= actual-observed <= 2_000_000_000:
        raise RuntimeError('the guest calendar differs from independently observed RTC hardware')

# SPDX-License-Identifier: GPL-3.0-or-later
"""Read complete ordinary-init seed records from the actual console stream."""
import re


def seed_records(text, event):
    status = r' status=(\d+)' if event == 'REAP' else ''
    return re.findall(r'^(?:/ # )?INIT_RANDOM_SEED_' + event + r' pid=(\d+)' + status +
                      r' monotonic_ms=(\d+)\r?\n', text, re.MULTILINE)

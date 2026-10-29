# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixed application contracts for complete Internet stream control matrices."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Contract:
    source: str
    program: str
    label: str
    marker: str

    @property
    def failure(self):
        return self.label + '_FAIL'


ABI = Contract('userspace/tests/net/tcp6/abi.c', 'tcp6-abi', 'TCP6_ABI',
    'TCP6_ABI_PASS address_cases=72 option_cases=10 name_cases=16 copy_cases=102')
STATE = Contract('userspace/tests/net/tcp6/control_state.c', 'tcp-control-state', 'TCP_CONTROL_STATE',
    'TCP_CONTROL_STATE_PASS loopback_only=1 snapshots=51 queries=236 exchanges=12 copy_cases=50')

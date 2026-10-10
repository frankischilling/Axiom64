# SPDX-License-Identifier: GPL-3.0-or-later
"""Select a VM accelerator and record what QEMU actually initialized."""
import os


class Acceleration:
    def __init__(self, requested=None):
        if requested is None:
            requested = os.environ.get('AXIOM64_QEMU_ACCELERATOR', 'tcg')
        if requested not in ('tcg', 'auto', 'kvm'):
            raise ValueError('AXIOM64_QEMU_ACCELERATOR must be tcg, auto or kvm')
        self.requested = requested
        self.evidence = dict(requested=requested, used=None, kvm_present=None)

    @property
    def machine(self):
        return 'pc,accel=' + ('kvm:tcg' if self.requested == 'auto' else self.requested)

    def observe(self, monitor):
        state = monitor.command('query-kvm')
        if (not isinstance(state, dict) or type(state.get('enabled')) is not bool or
                type(state.get('present')) is not bool):
            raise ValueError('QEMU did not report a valid accelerator state')
        used = 'kvm' if state['enabled'] else 'tcg'
        self.evidence = dict(requested=self.requested, used=used, kvm_present=state['present'])
        if self.requested != 'auto' and used != self.requested:
            raise ValueError('QEMU accelerator does not match the required configuration')
        return self.evidence

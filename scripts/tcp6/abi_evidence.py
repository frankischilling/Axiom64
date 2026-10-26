# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently reopen the complete IPv6 TCP address and copy comparison."""
import json
from pathlib import Path
from tcp6.control_contract import ABI
from tcp6.matrix_evidence import audit_matrix, require

MARKER = ABI.marker
WSL_KERNEL = '6.6.87.2-microsoft-standard-WSL2'
PRECHECK = ('TCP6_ABI_NATIVE_PRECHECK kernel=' + WSL_KERNEL +
            ' family=17 short_cases=6 errno=97')


def audit(directory):
    directory = Path(directory)
    result = audit_matrix(directory, ABI)
    for profile in ('static', 'dynamic'):
        for environment in ('native', 'bios', 'uefi'):
            before = json.loads((directory / profile / (environment + '-before.json')).read_text())
            name = 'native.log' if environment == 'native' else environment + '.log'
            lines = (directory / profile / name).read_text().splitlines()
            observed = [line for line in lines if line.startswith('TCP6_ABI_NATIVE_PRECHECK')]
            expected = [PRECHECK] if environment == 'native' and before['kernel'] == WSL_KERNEL else []
            require(observed == expected, 'exact native-only packet-family prevalidation profile')
    result['cases_each'] = 200
    return result

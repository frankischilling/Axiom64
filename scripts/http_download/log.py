# SPDX-License-Identifier: GPL-3.0-or-later
"""Require the observed firmware and reject guest fault diagnostics."""
import re

from tcp_fault_capture import require

FAILURES = (b'PANIC:', b'FAULT ', b'ABI_FAIL', b'IPC_FAIL', b'SIGNAL_FAIL', b'VFS_FAIL',
            b'THREAD_FAIL', b'THREAD_IO_FAIL', b'FUTEX_FAIL', b'LIFECYCLE_FAIL', b'X11_FAIL',
            b'BOOT_ROOT_FAIL', b'FILESYSTEM_SHUTDOWN_FAIL', b'ACCOUNT_NORMAL_FAIL',
            b'DESKTOP_LOGIN_FAIL', b'EVENTFD_FAIL', b'DOWNLOAD_CLIENT_FAIL')


def fault_free(data):
    require(not any(marker in data for marker in FAILURES) and
            not re.search(rb'assert(?:ion)?[^\r\n]{0,200}failed', data, re.I),
            'guest fault diagnostics and failed assertions reject the download run')


def healthy(data, firmware):
    observed = re.findall(rb'^Firmware: (BIOS|UEFI)\r*$', data, re.M)
    require(observed == [firmware.upper().encode()], 'actual guest firmware identity')
    fault_free(data)
    return dict(passed=True, observed_firmware=firmware, fault_diagnostics_rejected=True)

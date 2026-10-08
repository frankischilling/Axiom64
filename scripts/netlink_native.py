"""Compare route socket contracts with Linux inside a private network namespace."""
import ctypes
import json
import os
import platform
import subprocess
import time
from fetch import ROOT


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo after make build/netlink-native; a private network namespace needs root.')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.unshare.argtypes = [ctypes.c_int]
    libc.unshare.restype = ctypes.c_int
    if libc.unshare(0x40000000) != 0:  # CLONE_NEWNET; never change host interfaces/routes.
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    for name in ['eth0', 'eth1']:
        subprocess.run(['ip', 'link', 'add', name, 'type', 'dummy'], check=True)
    started = time.monotonic()
    process = subprocess.run([str(ROOT / 'build/netlink-native'), '--native'],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
    log = ROOT / 'build/netlink-native.log'
    log.write_bytes(process.stdout)
    text = process.stdout.decode(errors='replace')
    print(text, end='', flush=True)
    names = ['LIFECYCLE', 'FORK_LIFETIME', 'MESSAGE_IO', 'UNCAPPED_REPLY',
             'ROUTE_OWNERSHIP', 'CONFIGURATION_ADAPTER', 'TESTS']
    missing = [f'NETLINK_{name}_PASS' for name in names if f'NETLINK_{name}_PASS' not in text]
    result = dict(kernel=platform.release(), returncode=process.returncode, missing=missing,
                  seconds=round(time.monotonic() - started, 3),
                  passed=process.returncode == 0 and not missing)
    (ROOT / 'build/netlink-native-results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)
    if not result['passed']:
        raise SystemExit('Native Linux route socket comparison failed')


if __name__ == '__main__':
    main()

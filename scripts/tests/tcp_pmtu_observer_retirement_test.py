# SPDX-License-Identifier: GPL-3.0-or-later
"""Inject a real frame after the production PMTU observer's final thread drain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/tcp-pmtu-observer-retirement')
    args = parser.parse_args()
    if os.geteuid():
        parser.error('observer retirement requires isolated native root network namespaces')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'userspace/tests/net/tcp_pmtu.c'
    original = source.read_bytes()
    (directory / 'tcp_pmtu.c').write_bytes(original)
    wrapper = directory / 'retirement.c'
    wrapper.write_text(r'''#define main full_pmtu_main
#include "tcp_pmtu.c"
#undef main

int __real_pthread_join(pthread_t, void**);
ssize_t __real_recvfrom(int, void*, size_t, int, struct sockaddr*, socklen_t*);
static unsigned late_received[2];

ssize_t __wrap_recvfrom(int fd, void* buffer, size_t capacity, int flags,
                        struct sockaddr* address, socklen_t* address_length) {
    ssize_t length = __real_recvfrom(fd, buffer, capacity, flags, address, address_length);
    unsigned char* frame = buffer;
    if (length >= 14 && frame[12] == 0x88 && frame[13] == 0xb5) {
        unsigned lane = fd == observers[0] ? 0 : 1;
        unsigned char expected[60] = {0};
        expected[0] = expected[6] = 0x52;
        expected[1] = expected[7] = 0x54;
        expected[5] = expected[11] = 0x10 + lane;
        expected[12] = 0x88;
        expected[13] = 0xb5;
        CHECK(fd == observers[lane] && length == sizeof(expected) &&
              !memcmp(frame, expected, sizeof(expected)));
        late_received[lane]++;
    }
    return length;
}

int __wrap_pthread_join(pthread_t thread, void** result) {
    int status = __real_pthread_join(thread, result);
    CHECK(status == 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        int sender = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(0x88b5));
        CHECK(sender >= 0);
        unsigned char frame[60] = {0};
        frame[0] = frame[6] = 0x52;
        frame[1] = frame[7] = 0x54;
        frame[5] = frame[11] = 0x10 + lane;
        frame[12] = 0x88;
        frame[13] = 0xb5;
        struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                     .sll_protocol = htons(0x88b5),
                                     .sll_ifindex = (int)indices[lane],
                                     .sll_halen = 6};
        memcpy(target.sll_addr, frame, 6);
        CHECK(sendto(sender, frame, sizeof(frame), 0, (void*)&target, sizeof(target)) == sizeof(frame));
        CHECK(close(sender) == 0);
    }
    return status;
}

int main(void) {
    native = 1;
    capture_start();
    capture_stop();
    CHECK(late_received[0] == 1 && late_received[1] == 1);
    puts("TCP_PMTU_OBSERVER_RETIREMENT_PASS adapters=2 late_frames=2 zero_drops=1");
    return 0;
}
''')
    program = directory / 'retirement'
    command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               str(wrapper), '-Wl,--wrap=pthread_join', '-Wl,--wrap=recvfrom', '-o', str(program)]
    with (directory / 'build.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    setup = directory / 'namespace.sh'
    setup.write_text('set -eu\nip link set lo up\n'
                     'ip link add eth0 type dummy\nip link add eth1 type dummy\n'
                     'ip link set eth0 address 52:54:00:00:00:10 up\n'
                     'ip link set eth1 address 52:54:00:00:00:11 up\nexec "$1"\n')
    execution = ['unshare', '--net', 'sh', str(setup), str(program)]
    with (directory / 'actual.log').open('wb') as log:
        result = subprocess.run(execution, stdout=log, stderr=subprocess.STDOUT, timeout=15)
    text = (directory / 'actual.log').read_text()
    passed = result.returncode == 0 and text.splitlines().count(
        'TCP_PMTU_OBSERVER_RETIREMENT_PASS adapters=2 late_frames=2 zero_drops=1') == 1 and \
        text.count('PMTU_CAPTURE_PASS lane=') == 2 and 'TCP_FAULT_FAIL' not in text
    if source.read_bytes() != original:
        raise ValueError('production observer changed during the native retirement regression')
    record = dict(passed=passed, returncode=result.returncode, command=execution, compile=command,
                  kernel=platform.uname()._asdict(), source_sha256=digest(directory / 'tcp_pmtu.c'),
                  wrapper_sha256=digest(wrapper), binary_sha256=digest(program),
                  log_sha256=digest(directory / 'actual.log'))
    (directory / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
    print(text, end='')
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()

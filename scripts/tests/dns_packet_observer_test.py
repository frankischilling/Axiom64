# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the real DNS observer with both directions and late Ethernet frames."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/dns-packet-observer')
    args = parser.parse_args()
    if os.geteuid():
        parser.error('DNS observer regression requires isolated root network namespaces')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'userspace/tests/net/dns/contract.h'
    retained = directory / 'contract.h'
    original = source.read_bytes()
    retained.write_bytes(original)
    wrapper = directory / 'observer.c'
    wrapper.write_text(r'''#include "contract.h"

static struct capture captured;

static void send_frame(int sender, unsigned lane, int incoming, unsigned type) {
    char name[16];
    snprintf(name, sizeof(name), incoming ? "peer%u" : "eth%u", lane);
    unsigned index = if_nametoindex(name);
    check(index != 0, "regression interface index");
    unsigned char frame[60] = {0};
    const unsigned char guest[] = {0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane};
    const unsigned char peer[] = {2, 0x41, 0x58, 0x44, 0x4e, lane};
    memcpy(frame, incoming ? guest : peer, 6);
    memcpy(frame + 6, incoming ? peer : guest, 6);
    frame[12] = type >> 8;
    frame[13] = type;
    for (unsigned at = 14; at < sizeof(frame); at++)
        frame[at] = at ^ lane ^ incoming ^ type;
    struct sockaddr_ll target = {.sll_family = AF_PACKET, .sll_protocol = htons(type),
                                .sll_ifindex = (int)index, .sll_halen = 6};
    memcpy(target.sll_addr, frame, 6);
    check(sendto(sender, frame, sizeof(frame), 0, (void*)&target, sizeof(target)) ==
              sizeof(frame), "regression complete Ethernet send");
}

int __real_pthread_join(pthread_t, void**);

int __wrap_pthread_join(pthread_t thread, void** result) {
    int status = __real_pthread_join(thread, result);
    check(status == 0, "regression original observer join");
    int sender = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    check(sender >= 0, "regression late sender");
    for (unsigned lane = 0; lane < 2; lane++)
        send_frame(sender, lane, 0, 0x800);
    check(close(sender) == 0, "regression late sender close");
    return status;
}

int main(void) {
    setbuf(stdout, NULL);
    // Reference unused helpers so -Werror also checks the actual complete header.
    (void)configure;
    (void)resolver;
    (void)lookup;
    capture_start(&captured);
    int sender = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    check(sender >= 0, "regression sender");
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned link = 0; link < 2; link++)
            for (unsigned incoming = 0; incoming < 2; incoming++)
                send_frame(sender, lane, incoming, link ? 0x88b5 : 0x800);
    check(close(sender) == 0, "regression sender close");
    capture_stop(&captured);
    printf("DNS_OBSERVER_RESULT packets=%u,%u total=%u\n",
           captured.packets[0], captured.packets[1], captured.count);
    return captured.packets[0] == 5 && captured.packets[1] == 5 && captured.count == 10 ? 0 : 1;
}
''')
    setup = directory / 'namespace.sh'
    setup.write_text('set -eu\n'
                     'echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6\n'
                     'echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6\n'
                     'for lane in 0 1; do\n'
                     'ip link add eth${lane} type veth peer name peer${lane}\n'
                     'done\n'
                     'ip link set eth0 address 52:54:00:12:34:10 up\n'
                     'ip link set eth1 address 52:54:00:12:34:11 up\n'
                     'ip link set peer0 address 02:41:58:44:4e:00 up\n'
                     'ip link set peer1 address 02:41:58:44:4e:01 up\n'
                     'exec "$1"\n')
    program = directory / 'observer'
    command = ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
               str(wrapper), '-Wl,--wrap=pthread_join', '-o', str(program)]
    with (directory / 'compile.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    execution = ['unshare', '--net', 'sh', str(setup), str(program)]
    output = directory / 'serial.log'
    with output.open('wb') as log:
        actual = subprocess.run(execution, stdout=log, stderr=subprocess.STDOUT, timeout=15)
    text = output.read_text()
    passed = actual.returncode == 0 and text.splitlines().count(
        'DNS_OBSERVER_RESULT packets=5,5 total=10') == 1
    if source.read_bytes() != original:
        raise ValueError('DNS observer source changed during regression')
    proof = dict(passed=passed, returncode=actual.returncode, kernel=platform.uname()._asdict(),
                 compile=command, command=execution,
                 source_sha256=hashlib.sha256(original).hexdigest(),
                 log_sha256=hashlib.sha256(output.read_bytes()).hexdigest())
    (directory / 'receipt.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof), flush=True)
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()

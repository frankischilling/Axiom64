# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise all three real TCP observers with incoming and outgoing raw frames."""
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
    parser.add_argument('--directory', type=Path, default=ROOT / 'build/tcp-packet-observers')
    args = parser.parse_args()
    if os.geteuid():
        parser.error('packet observers require isolated root network namespaces')
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    wrapper = directory / 'observer.c'
    wrapper.write_text(r'''// Renaming an unused C main removes its implicit return-zero rule.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
#define main full_application_main
#include OBSERVER_FILE
#undef main
#pragma GCC diagnostic pop

int __real_pthread_join(pthread_t, void**);

int __wrap_pthread_join(pthread_t thread, void** result) {
    int status = __real_pthread_join(thread, result);
    CHECK(status == 0);
    int sender = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    CHECK(sender >= 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        unsigned char frame[60] = {0};
        const unsigned char guest[] = {0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane};
        const unsigned char peer[] = {2, 0x41, 0x58, 0x54, 0x43, lane};
        memcpy(frame, peer, 6);
        memcpy(frame + 6, guest, 6);
        frame[12] = 8;
        // Generated observer-only IPv4 Ethernet payload; no TCP scenario.
        frame[14] = 0x50;
        struct sockaddr_ll target = {.sll_family = AF_PACKET,
            .sll_protocol = htons(0x800), .sll_ifindex = (int)indices[lane], .sll_halen = 6};
        memcpy(target.sll_addr, peer, 6);
        CHECK(sendto(sender, frame, sizeof(frame), 0, (void*)&target, sizeof(target)) == sizeof(frame));
    }
    CHECK(close(sender) == 0);
    return status;
}

int main(int argc, char** argv) {
    CHECK(argc == 2);
    setbuf(stdout, NULL);
#ifdef PRESSURE_OBSERVER
    native_capture = atoi(argv[1]);
#else
    native = atoi(argv[1]);
#endif
    capture_start();
    int sender = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
    CHECK(sender >= 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        char name[16];
        snprintf(name, sizeof(name), "peer%u", lane);
        unsigned peer_index = if_nametoindex(name);
        CHECK(peer_index);
        for (unsigned link = 0; link < 2; link++) {
            for (unsigned incoming = 0; incoming < 2; incoming++) {
                unsigned char frame[60] = {0};
                const unsigned char guest[] = {0x52, 0x54, 0, 0x12, 0x34, 0x10 + lane};
                const unsigned char peer[] = {2, 0x41, 0x58, 0x54, 0x43, lane};
                memcpy(frame, incoming ? guest : peer, 6);
                memcpy(frame + 6, incoming ? peer : guest, 6);
                frame[12] = link ? 0x88 : 8;
                frame[13] = link ? 0xb5 : 0;
                for (unsigned at = 14; at < sizeof(frame); at++)
                    frame[at] = at ^ lane ^ link ^ incoming;
                struct sockaddr_ll target = {.sll_family = AF_PACKET,
                    .sll_protocol = htons(link ? 0x88b5 : 0x800),
                    .sll_ifindex = (int)(incoming ? peer_index : indices[lane]), .sll_halen = 6};
                memcpy(target.sll_addr, frame, 6);
                CHECK(sendto(sender, frame, sizeof(frame), 0, (void*)&target, sizeof(target)) ==
                      sizeof(frame));
            }
        }
    }
    CHECK(close(sender) == 0);
    capture_stop();
    printf("TCP_PACKET_OBSERVER_RESULT mode=%s ipv4=%u,%u observed=%u,%u\n", argv[1],
           ipv4_frames[0], ipv4_frames[1], observed[0], observed[1]);
    return ipv4_frames[0] == 3 && ipv4_frames[1] == 3 &&
           observed[0] == 5 && observed[1] == 5 ? 0 : 1;
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
                     'ip link set peer0 address 02:41:58:54:43:00 up\n'
                     'ip link set peer1 address 02:41:58:54:43:01 up\n'
                     'exec "$1" "$2"\n')
    results = []
    for name in ('icmp', 'pmtu', 'pressure'):
        source = ROOT / f'userspace/tests/net/tcp_{name}.c'
        original = source.read_bytes()
        retained = directory / source.name
        retained.write_bytes(original)
        if name == 'icmp':
            (directory / 'tcp_icmp_cases.h').write_bytes(
                (ROOT / 'userspace/tests/net/tcp_icmp_cases.h').read_bytes())
        program = directory / name
        command = ['gcc', '-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-pthread',
                   '-DOBSERVER_FILE="' + str(retained) + '"',
                   *(['-DPRESSURE_OBSERVER'] if name == 'pressure' else []),
                   str(wrapper), '-Wl,--wrap=pthread_join', '-o', str(program)]
        with (directory / f'{name}-build.log').open('wb') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
        for mode in ('0', '1'):
            log_path = directory / f'{name}-{mode}.log'
            execution = ['unshare', '--net', 'sh', str(setup), str(program), mode]
            with log_path.open('wb') as log:
                actual = subprocess.run(execution, stdout=log, stderr=subprocess.STDOUT, timeout=15)
            text = log_path.read_text()
            passed = actual.returncode == 0 and text.splitlines().count(
                f'TCP_PACKET_OBSERVER_RESULT mode={mode} ipv4=3,3 observed=5,5') == 1
            if name == 'icmp' and passed:
                lines = text.splitlines()
                frames = [index for index, line in enumerate(lines) if line.startswith('ICMP_FRAME ')]
                end = [index for index, line in enumerate(lines) if line.startswith('ICMP_CAPTURE_CLOCK phase=end ')]
                passed = len(frames) == 6 and len(end) == 1 and max(frames) < end[0]
            row = dict(observer=name, mode=int(mode), passed=passed, returncode=actual.returncode,
                       compile=command, command=execution,
                       source_sha256=hashlib.sha256(original).hexdigest(),
                       log_sha256=hashlib.sha256(log_path.read_bytes()).hexdigest())
            results.append(row)
            print(json.dumps(row), flush=True)
        if source.read_bytes() != original:
            raise ValueError('TCP observer source changed during the regression')
    value = dict(passed=all(row['passed'] for row in results), cases=len(results),
                 kernel=platform.uname()._asdict(), reports=results,
                 scope='actual packet observer regression with generated Ethernet frames')
    (directory / 'receipt.json').write_text(json.dumps(value, indent=2) + '\n')
    raise SystemExit(0 if value['passed'] else 1)


if __name__ == '__main__':
    main()

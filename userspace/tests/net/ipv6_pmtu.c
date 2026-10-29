// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_PMTU"
#define IPV6_BARRIER_PROTOCOL 0x88ba
#define IPV6_BARRIER_MAGIC "IP6P"
#include "ipv6_fixture.h"

static const unsigned char error_types[13] = {1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 4, 4, 4};
static const unsigned char error_codes[13] = {0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 0, 1, 2};
static const int error_results[13] = {0,      EACCES, 0, 0,      ECONNREFUSED, EACCES, EACCES,
                                      EPROTO, 0,      0, EPROTO, EPROTO,       EPROTO};

static void run(unsigned lane) {
    unsigned char bytes[1300];
    for (unsigned sequence = 0; sequence < 60; sequence++) {
        int pmtu = sequence < 24;
        unsigned kind = pmtu            ? sequence / 12 + 2
                        : sequence < 50 ? (sequence - 24) / 13 + 2
                                        : (sequence - 50) / 5 + 2;
        unsigned mode = pmtu ? sequence % 6 : 1;
        unsigned scoped = pmtu ? sequence % 12 / 6 : 0;
        int fd = create(kind);
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
              "PMTU device ownership");
        if (kind == SOCK_DGRAM)
            option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        option(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, mode);
        bind_address(fd, address(lane, 2, kind == SOCK_DGRAM ? 47000 + sequence : 0, scoped));
        connect_address(
            fd, address(lane, 16 + sequence, kind == SOCK_DGRAM ? 48000 + sequence : 58, scoped));
        unsigned length = pmtu ? sizeof(bytes) : 16;
        for (unsigned n = 0; n < length; n++)
            bytes[n] = n * 19 + sequence * 3 + lane;
        if (kind == SOCK_RAW) {
            bytes[0] = 129;
            bytes[1] = bytes[2] = bytes[3] = 0;
        }
        check(get(fd, IPPROTO_IPV6, IPV6_MTU) == 1500, "fresh destination path MTU");
        barrier(lane, sequence * 3 + 1);
        check(send(fd, bytes, length, 0) == (ssize_t)length, "original quoted datagram");
        barrier(lane, sequence * 3 + 2);
        int mtu = get(fd, IPPROTO_IPV6, IPV6_MTU);
        int error = get(fd, SOL_SOCKET, SO_ERROR);
        int wanted_mtu = pmtu && (kind == SOCK_RAW || mode < 4) ? 1280 : 1500;
        int wanted_error =
            pmtu            ? (kind == SOCK_RAW ? mode == 2 : mode > 0 && mode < 4) ? EMSGSIZE : 0
            : sequence < 50 ? error_results[(sequence - 24) % 13]
                            : 0;
        unsigned error_type = pmtu ? 2 : sequence < 50 ? error_types[(sequence - 24) % 13] : 1;
        unsigned error_code = pmtu ? 0 : sequence < 50 ? error_codes[(sequence - 24) % 13] : 4;
        printf("IPV6_PMTU_ERROR lane=%u case=%u type=%u scope=%u mode=%u icmp=%u code=%u mtu=%d "
               "errno=%d\n",
               lane, sequence, kind, scoped, mode, error_type, error_code, mtu, error);
        fflush(stdout);
        check(mtu == wanted_mtu && error == wanted_error && !get(fd, SOL_SOCKET, SO_ERROR),
              "native learned MTU and consumed quoted error");
        if (pmtu) {
            errno = 0;
            ssize_t sent = send(fd, bytes, length, 0);
            int send_error = sent < 0 ? errno : 0;
            printf("IPV6_PMTU_SEND lane=%u case=%u result=%ld errno=%d\n", lane, sequence,
                   (long)sent, send_error);
            check(mode == 2 ? sent == -1 && send_error == EMSGSIZE : sent == (ssize_t)length,
                  "learned path controls actual output");
        }
        barrier(lane, sequence * 3 + 3);
        check(!close(fd), "retire quoted socket description");
    }
    printf("IPV6_PMTU_WIRE_PASS lane=%u cases=60 policies=6 scopes=2\n", lane);
}

int main(void) {
    int control = fixture_interfaces();
    for (unsigned lane = 0; lane < 2; lane++)
        run(lane);
    close(control);
    for (unsigned lane = 0; lane < 2; lane++)
        close(packets[lane]);
    puts("IPV6_PMTU_PASS adapters=2 cases=120 policies=6 malformed_each=10");
}

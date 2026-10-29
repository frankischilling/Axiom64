// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_OUTPUT"
#define IPV6_BARRIER_PROTOCOL 0x88b8
#define IPV6_BARRIER_MAGIC "IP6O"
#include "ipv6_fixture.h"

static void option_result(int type, unsigned number, int result, int wanted_error) {
    int error = result < 0 ? errno : 0;
    printf("IPV6_OUTPUT_OPTION_CASE type=%d case=%u result=%d errno=%d\n", type, number, result,
           error);
    check(wanted_error ? result == -1 && error == wanted_error : result == 0,
          "output option argument and copy contract");
}

static void option_contract(void) {
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && !mprotect(pages + 4096, 4096, PROT_NONE),
          "output option fault fixture");
    pages[4095] = 1;
    for (int type = SOCK_DGRAM; type <= SOCK_RAW; type++) {
        int fd = create(type), value = -1;
        unsigned number = 0;
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, NULL, 0), 0);
        check(!get(fd, IPPROTO_IPV6, IPV6_DONTFRAG), "empty boolean option clears policy");
        for (unsigned length = 1; length <= 3; length++) {
            option(fd, IPPROTO_IPV6, IPV6_DONTFRAG, 1);
            option_result(type, number++,
                          setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, pages + 4095, length), 0);
            check(!get(fd, IPPROTO_IPV6, IPV6_DONTFRAG),
                  "short boolean ignores payload and clears policy");
        }
        option_result(type, number++,
                      setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &value, (socklen_t)-1), EINVAL);
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, pages + 4096, 4),
                      EFAULT);
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value, 4),
                      EINVAL);
        value = 6;
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value, 4),
                      EINVAL);
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &value, 3),
                      EINVAL);
        option_result(type, number++,
                      setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, pages + 4096, 3), EINVAL);
        option_result(type, number++,
                      setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, pages + 4096, 4), EFAULT);
        check(get(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER) == IPV6_PMTUDISC_WANT,
              "invalid discovery mode preserves state");
        value = -1;
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &value, 4), EINVAL);
        value = 1279;
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &value, 4), EINVAL);
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, pages + 4096, 3),
                      EINVAL);
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, pages + 4096, 4),
                      EFAULT);
        value = 1280;
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &value, 4), 0);
        value = 0;
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, &value, 4), 0);
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, pages + 4096, 3),
                      0);
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, NULL, 4), 0);
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, NULL, 4), 0);
        check(!get(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER), "null discovery value selects zero");
        option_result(type, number++, setsockopt(fd, IPPROTO_IPV6, IPV6_MTU, NULL, 4), 0);
        check(number == 21, "complete output option case inventory");
        close(fd);
    }
    check(!munmap(pages, 8192), "release output option fault fixture");
    puts("IPV6_OUTPUT_OPTIONS_PASS cases=42");
}

static void put32(unsigned char* bytes, uint32_t value) {
    for (unsigned n = 0; n < 4; n++)
        bytes[n] = value >> (24 - n * 8);
}

static void event(unsigned lane, unsigned kind, unsigned sequence, int type, unsigned scoped,
                  unsigned configuration, unsigned length) {
    unsigned char frame[60] = {2, 'I', 'P', '6', lane, 0};
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = 0x88;
    frame[13] = 0xb9;
    memcpy(frame + 14, "IP6O", 4);
    frame[18] = lane;
    frame[19] = kind;
    put32(frame + 20, sequence);
    put32(frame + 24, length);
    frame[28] = type;
    frame[29] = scoped;
    frame[30] = configuration;
    struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                 .sll_protocol = htons(0x88b9),
                                 .sll_ifindex = indices[lane],
                                 .sll_halen = 6};
    memcpy(target.sll_addr, frame, 6);
    check(sendto(packets[lane], frame, sizeof(frame), 0, (void*)&target, sizeof(target)) ==
              sizeof(frame),
          "output case boundary");
    unsigned char expected[60], reply[1600];
    memcpy(expected, frame, sizeof(frame));
    memcpy(expected, frame + 6, 6);
    memcpy(expected + 6, frame, 6);
    expected[32] = 1;
    uint64_t began = now();
    for (;;) {
        readable(packets[lane], POLLIN);
        ssize_t size = recv(packets[lane], reply, sizeof(reply), MSG_DONTWAIT);
        if (size == sizeof(expected) && !memcmp(reply, expected, sizeof(expected)))
            break;
        check(now() - began < 10000000000ULL, "finite output boundary acknowledgement");
    }
}

static void output(unsigned lane) {
    unsigned char* bytes = malloc(65536);
    check(bytes != NULL, "owned output data");
    unsigned sequence = 0;
    for (int type = SOCK_DGRAM; type <= SOCK_RAW; type++) {
        for (unsigned scoped = 0; scoped < 2; scoped++) {
            for (unsigned configuration = 0; configuration < 9; configuration++) {
                unsigned lengths[6] = {0, 1452, 1453, 1472, 65527, 65528};
                if (type == SOCK_RAW) {
                    unsigned raw_lengths[6] = {4, 1460, 1461, 1472, 65535, 65536};
                    memcpy(lengths, raw_lengths, sizeof(lengths));
                }
                for (unsigned n = 0; n < 6; n++, sequence++) {
                    unsigned length = lengths[n];
                    int fd =
                        wire_socket(lane, type, 45000 + lane + scoped * 10,
                                    type == SOCK_RAW ? 58 : 46000 + lane + scoped * 10, scoped);
                    check(get(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER) == IPV6_PMTUDISC_WANT &&
                              !get(fd, IPPROTO_IPV6, IPV6_DONTFRAG),
                          "default output policy");
                    unsigned mode =
                        configuration >= 1 && configuration <= 6 ? configuration - 1 : 1;
                    if (configuration >= 1 && configuration <= 6)
                        option(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, mode);
                    if (configuration == 7)
                        option(fd, IPPROTO_IPV6, IPV6_DONTFRAG, 1);
                    if (configuration == 8)
                        option(fd, IPPROTO_IPV6, IPV6_MTU, 1280);
                    check(get(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER) == (int)mode &&
                              get(fd, IPPROTO_IPV6, IPV6_DONTFRAG) == (configuration == 7) &&
                              get(fd, IPPROTO_IPV6, IPV6_MTU) == 1500,
                          "retained output option values");
                    option(fd, SOL_SOCKET, SO_SNDBUF, 65536);
                    check(get(fd, SOL_SOCKET, SO_SNDBUF) == 131072,
                          "large datagram send allowance");
                    for (unsigned at = 0; at < length; at++)
                        bytes[at] = (unsigned char)(at * 17 + sequence * 7 + lane);
                    if (type == SOCK_RAW) {
                        bytes[0] = 129;
                        bytes[1] = bytes[2] = bytes[3] = 0;
                    }
                    event(lane, 2, sequence, type, scoped, configuration, length);
                    int alias = dup(fd);
                    check(alias >= 0 && !close(fd), "shared output description");
                    struct iovec vectors[3] = {
                        {bytes, 0}, {bytes, length ? 1 : 0}, {bytes + 1, length ? length - 1 : 0}};
                    struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 3};
                    errno = 0;
                    ssize_t sent =
                        sequence & 1 ? sendmsg(alias, &message, 0) : send(alias, bytes, length, 0);
                    int error = sent < 0 ? errno : 0;
                    unsigned overhead = type == SOCK_DGRAM ? 48 : 40;
                    unsigned mtu = configuration == 8 ? 1280 : 1500;
                    int fragmentable = configuration != 7 && (mode < 2 || mode == 5);
                    int expected = length > (type == SOCK_DGRAM ? 65527u : 65535u) ||
                                           (!fragmentable && length + overhead > mtu)
                                       ? EMSGSIZE
                                       : 0;
                    printf("IPV6_OUTPUT_CASE lane=%u case=%u type=%d scope=%u configuration=%u "
                           "bytes=%u result=%ld errno=%d\n",
                           lane, sequence, type, scoped, configuration, length, (long)sent, error);
                    check(expected ? sent == -1 && error == expected : sent == (ssize_t)length,
                          "native output size and policy result");
                    if (!expected)
                        option(alias, IPPROTO_IPV6, IPV6_DONTFRAG, 1);
                    check(!close(alias), "retire queued output owner");
                    int reused = create(type);
                    event(lane, 3, sequence, type, scoped, configuration, length);
                    check(!get(reused, SOL_SOCKET, SO_ERROR),
                          "retired owner cannot affect reused description");
                    close(reused);
                }
            }
        }
    }
    check(sequence == 216, "complete source output case inventory");
    free(bytes);
    printf("IPV6_OUTPUT_WIRE_PASS lane=%u cases=216 maximum_raw=65535 maximum_UDP=65527\n", lane);
}

int ipv6_send_controls_local(void);
int ipv6_send_controls_wire(const unsigned* input_indices, const unsigned char* input_macs,
                            const int* input_packets);

int ipv6_extension_wire(const unsigned* input_indices, const unsigned char* input_macs,
                        const int* input_packets);

int ipv6_routing_wire(const unsigned* input_indices, const unsigned char* input_macs,
                      const int* input_packets);

int ipv6_extension_controls_local(void);
int ipv6_sticky_controls_local(void);
int ipv6_sticky_wire(const unsigned* input_indices, const unsigned char* input_macs,
                     const int* input_packets);

int main(void) {
    check(!ipv6_send_controls_local(), "complete per-message send controls");
    check(!ipv6_extension_controls_local(),
          "complete local extension admission and receive controls");
    check(!ipv6_sticky_controls_local(), "complete sticky extension observations");
    option_contract();
    int control = fixture_interfaces();
    for (unsigned lane = 0; lane < 2; lane++)
        output(lane);
    check(!ipv6_send_controls_wire(indices, &macs[0][0], packets),
          "complete Ethernet send controls");
    check(!ipv6_extension_wire(indices, &macs[0][0], packets),
          "complete Ethernet extension controls");
    check(!ipv6_routing_wire(indices, &macs[0][0], packets),
          "complete type-2 routing Ethernet controls");
    check(!ipv6_sticky_wire(indices, &macs[0][0], packets),
          "complete sticky extension Ethernet controls");
    close(control);
    for (unsigned lane = 0; lane < 2; lane++)
        close(packets[lane]);
    puts(
        "IPV6_OUTPUT_PASS adapters=2 cases=432 policies=9 scopes=2 copied_vectors=1 close_reuse=1");
}

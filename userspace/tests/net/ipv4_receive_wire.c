// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_receive_wire_fixture.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

void wire_check(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "IPV4_RECEIVE_WIRE_FAIL %s errno=%d\n", label, errno);
        exit(1);
    }
}

void wire_hex(const void* value, size_t size) {
    const unsigned char* bytes = value;
    for (size_t n = 0; n < size; n++)
        printf("%02x", bytes[n]);
}

static uint64_t monotonic(void) {
    struct timespec value;
    wire_check(!clock_gettime(CLOCK_MONOTONIC, &value), "actual monotonic clock");
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

static void exchange(unsigned lane, unsigned sequence, char phase) {
    unsigned char peer[6] = {2, 0x41, 0x58, 0x52, 0x58, (unsigned char)lane};
    unsigned char frame[60] = {0};
    memcpy(frame, peer, 6);
    memcpy(frame + 6, wire_links[lane].mac, 6);
    frame[12] = 0x88;
    frame[13] = 0xb9;
    memcpy(frame + 14, "AXR", 3);
    frame[17] = phase;
    frame[18] = lane;
    frame[19] = sequence;
    struct sockaddr_ll destination = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(0x88b9),
                                      .sll_ifindex = (int)wire_links[lane].index,
                                      .sll_halen = 6};
    memcpy(destination.sll_addr, peer, 6);
    wire_check(sendto(wire_links[lane].control, frame, sizeof(frame), 0,
                      (struct sockaddr*)&destination, sizeof(destination)) == sizeof(frame),
               "physical metadata barrier");
    uint64_t began = monotonic();
    for (;;) {
        struct pollfd ready = {.fd = wire_links[lane].control, .events = POLLIN};
        wire_check(poll(&ready, 1, 100) >= 0, "barrier readiness");
        unsigned char reply[128];
        ssize_t size = recv(wire_links[lane].control, reply, sizeof(reply), MSG_DONTWAIT);
        if (size >= 21 && !memcmp(reply + 14, "AXRA", 4)) {
            wire_check(size == 60 && !memcmp(reply, wire_links[lane].mac, 6) &&
                           !memcmp(reply + 6, peer, 6) && reply[12] == 0x88 && reply[13] == 0xb9 &&
                           reply[18] == lane && reply[19] == sequence &&
                           reply[20] == (unsigned char)phase,
                       "matching physical barrier acknowledgment");
            return;
        }
        wire_check(monotonic() - began < 10000000000ULL, "finite physical barrier deadline");
    }
}

static void options(int fd, unsigned mask) {
    const int names[] = {IP_PKTINFO, IP_RECVTTL, IP_RECVTOS};
    for (unsigned n = 0; n < 3; n++) {
        int value = !!(mask & (1u << n));
        wire_check(!setsockopt(fd, IPPROTO_IP, names[n], &value, sizeof(value)),
                   "receive option selection");
    }
}

static int receiver(unsigned lane, unsigned kind, unsigned sequence, uint32_t destination) {
    int fd = socket(AF_INET, (kind ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC,
                    kind == 1 ? IPPROTO_ICMP : IPPROTO_UDP);
    wire_check(fd >= 0, "real metadata receive description");
    char name[IFNAMSIZ];
    snprintf(name, sizeof(name), "eth%u", lane);
    wire_check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
               "actual receive interface binding");
    struct sockaddr_in local = {.sin_family = AF_INET,
                                .sin_port = kind ? 0 : htons(46000 + sequence)};
    wire_check(!bind(fd, (struct sockaddr*)&local, sizeof(local)),
               "wildcard metadata address binding");
    if ((destination >> 28) == 14) {
        struct ip_mreqn membership = {.imr_multiaddr.s_addr = htonl(destination),
                                      .imr_ifindex = (int)wire_links[lane].index};
        wire_check(!setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &membership, sizeof(membership)),
                   "physical multicast interest");
    }
    return fd;
}

static unsigned checksum(const unsigned char* data, size_t size) {
    unsigned result = 0;
    for (size_t at = 0; at < size; at += 2)
        result += (unsigned)data[at] * 256 + (at + 1 < size ? data[at + 1] : 0);
    while (result >> 16)
        result = (result & 65535) + (result >> 16);
    return (~result) & 65535;
}

static void sample(unsigned lane, unsigned sequence, unsigned kind, unsigned prepared,
                   unsigned scenario) {
    struct WireInput input = wire_input(lane, sequence, scenario);
    wire_transition(lane, sequence, scenario, 0);
    int fd = receiver(lane, kind, sequence, input.destination);
    int guard = kind == 2 ? receiver(lane, 0, sequence, input.destination) : -1;
    options(fd, prepared ? 1 : 0);
    exchange(lane, sequence, 'B');
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    unsigned char peek[64] = {0};
    size_t expected = kind ? 44 : 16;
    wire_check(poll(&ready, 1, 5000) == 1 && (ready.revents & POLLIN) &&
                   recv(fd, peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT) == (ssize_t)expected,
               "actual packet is queued before mutation and option changes");
    unsigned char body[16] = {'A',
                              'X',
                              'R',
                              'X',
                              'D',
                              'A',
                              'T',
                              'A',
                              (unsigned char)lane,
                              (unsigned char)sequence,
                              (unsigned char)kind,
                              (unsigned char)scenario,
                              (unsigned char)prepared,
                              1,
                              (unsigned char)(sequence ^ 0xa5),
                              (unsigned char)(0x5a + lane)};
    wire_check(!memcmp(peek + (kind ? 28 : 0), body, sizeof(body)),
               "queued original physical payload");
    exchange(lane, sequence, 'Q');
    wire_transition(lane, sequence, scenario, 1);
    options(fd, 7);
    unsigned char payload[64], controls[96];
    memset(payload, 0xa5, sizeof(payload));
    memset(controls, 0xa5, sizeof(controls));
    struct iovec vectors[2] = {{payload, 7}, {payload + 7, sizeof(payload) - 7}};
    struct sockaddr_in source;
    memset(&source, 0xa5, sizeof(source));
    struct msghdr message = {.msg_name = &source,
                             .msg_namelen = sizeof(source),
                             .msg_iov = vectors,
                             .msg_iovlen = 2,
                             .msg_control = controls,
                             .msg_controllen = sizeof(controls)};
    ssize_t result = recvmsg(fd, &message, MSG_DONTWAIT);
    wire_check(result == (ssize_t)expected && message.msg_namelen == sizeof(source) &&
                   source.sin_family == AF_INET && source.sin_addr.s_addr == htonl(input.source) &&
                   source.sin_port == (kind ? 0 : htons(42000 + sequence)),
               "original packet and source result");
    if (kind)
        wire_check(payload[0] == 0x45 && payload[1] == input.tos && payload[8] == input.ttl &&
                       payload[9] == (kind == 1 ? IPPROTO_ICMP : IPPROTO_UDP) &&
                       !checksum(payload, 20),
                   "actual complete raw IPv4 header");
    wire_check(!memcmp(payload + (kind ? 28 : 0), body, sizeof(body)),
               "original received physical payload");
    wire_check(message.msg_controllen <= sizeof(controls), "bounded physical receive controls");
    for (size_t at = message.msg_controllen; at < sizeof(controls); at++)
        wire_check(controls[at] == 0xa5, "unreported control bytes unchanged");
    for (size_t at = expected; at < sizeof(payload); at++)
        wire_check(payload[at] == 0xa5, "unwritten payload bytes unchanged");
    errno = 0;
    wire_check(recv(fd, peek, sizeof(peek), MSG_DONTWAIT) == -1 && errno == EAGAIN,
               "metadata receive consumed exactly one packet");
    printf("{\"kind\":\"receive-wire\",\"lane\":%u,\"case\":%u,\"transport\":%u,\"scenario\":%u,"
           "\"prepared\":%u,\"index\":%u,\"result\":%zd,\"flags\":%d,\"control_length\":%zu,"
           "\"control_hex\":\"",
           lane, sequence, kind, scenario, prepared, wire_links[lane].index, result,
           message.msg_flags, (size_t)message.msg_controllen);
    wire_hex(controls, message.msg_controllen);
    printf("\",\"payload\":\"");
    wire_hex(payload + (kind ? 28 : 0), sizeof(body));
    puts("\"}");
    if (guard >= 0) {
        ready.fd = guard;
        wire_check(poll(&ready, 1, 5000) == 1 &&
                       recv(guard, peek, sizeof(peek), MSG_DONTWAIT) == 16 &&
                       !memcmp(peek, body, sizeof(body)),
                   "raw UDP paired datagram delivery");
        wire_check(!close(guard), "close paired UDP interest");
    }
    wire_check(!close(fd), "close metadata description");
    wire_transition(lane, sequence, scenario, 2);
    exchange(lane, sequence, 'D');
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct utsname identity;
    wire_check(!uname(&identity), "actual kernel identity");
    printf("{\"kind\":\"kernel\",\"sysname\":\"%s\",\"release\":\"%s\"}\n", identity.sysname,
           identity.release);
    wire_configure();
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned kind = 0; kind < 3; kind++)
            for (unsigned prepared = 0; prepared < 2; prepared++)
                for (unsigned scenario = 0; scenario < WIRE_SCENARIOS; scenario++) {
                    unsigned sequence = (kind * 2 + prepared) * WIRE_SCENARIOS + scenario;
                    sample(lane, sequence, kind, prepared, scenario);
                }
        wire_check(!close(wire_links[lane].control), "close physical control description");
    }
    printf("IPV4_RECEIVE_WIRE_DONE lanes=2 cases_each=%u observations=%u\n", WIRE_CASES,
           WIRE_CASES * 2);
    return 0;
}

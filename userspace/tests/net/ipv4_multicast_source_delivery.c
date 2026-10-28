// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_multicast_source_delivery.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static const uint32_t group = 0xef7f2a01;
static unsigned actions, sends, received;

struct delivery {
    unsigned lane, index;
    int fd[8], alias[2], sender[2];
};

static void need(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "IPV4_SOURCE_WIRE_FAIL operation=%s errno=%d\n", operation, errno);
        exit(1);
    }
}

static unsigned long long now(void) {
    struct timespec clock;
    need(!clock_gettime(CLOCK_MONOTONIC, &clock), "delivery monotonic clock");
    return (unsigned long long)clock.tv_sec * 1000000000ULL + clock.tv_nsec;
}

static uint16_t get16(const unsigned char* bytes) {
    return (uint16_t)((unsigned)bytes[0] << 8 | bytes[1]);
}

static uint32_t get32(const unsigned char* bytes) {
    return (uint32_t)get16(bytes) << 16 | get16(bytes + 2);
}

static unsigned checksum(const unsigned char* bytes, unsigned count) {
    unsigned value = 0;
    for (unsigned n = 0; n < count; n += 2)
        value += (unsigned)bytes[n] << 8 | (n + 1 < count ? bytes[n + 1] : 0);
    while (value >> 16)
        value = (value & 65535) + (value >> 16);
    return value ^ 65535;
}

static uint32_t source(unsigned lane, unsigned which) {
    return 0x0a430101 + (lane << 8) + which * 2;
}

static int step(struct delivery* state, unsigned stage, const char* operation, int result,
                int descriptor) {
    int error = result < 0 ? errno : 0;
    printf("{\"kind\":\"delivery-action\",\"lane\":%u,\"stage\":%u,\"operation\":\"%s\","
           "\"returncode\":%d,\"errno\":%d}\n",
           state->lane, stage, operation, result, error);
    need(!error && (descriptor ? result >= 0 : result == 0), operation);
    actions++;
    return result;
}

static void all(int fd, int value) {
    need(!setsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &value, sizeof(value)),
         "delivery multicast-all policy");
    int observed = -1;
    socklen_t length = sizeof(observed);
    need(!getsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &observed, &length) &&
             length == sizeof(observed) && observed == value,
         "delivery multicast-all readback");
}

static int receiver(struct delivery* state, unsigned slot) {
    int raw = slot >= 4, one = 1;
    int fd = socket(AF_INET, (raw ? SOCK_RAW : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    raw ? IPPROTO_UDP : 0);
    need(fd >= 0, "delivery receive socket");
    need(!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)),
         "delivery shared receive address");
    char device[IFNAMSIZ];
    snprintf(device, sizeof(device), "eth%u", state->lane);
    need(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1),
         "delivery receive interface");
    struct sockaddr_in address = {
        .sin_family = AF_INET, .sin_port = htons(39901), .sin_addr.s_addr = htonl(group)};
    need(!bind(fd, (struct sockaddr*)&address, sizeof(address)), "delivery group address bind");
    all(fd, slot % 4 == 2);
    return fd;
}

static int sender(struct delivery* state, int raw) {
    int fd = socket(AF_INET, (raw ? SOCK_RAW : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    raw ? IPPROTO_UDP : 0);
    need(fd >= 0, "delivery output socket");
    struct sockaddr_in address = {.sin_family = AF_INET,
                                  .sin_port = htons(41000),
                                  .sin_addr.s_addr = htonl(0x0a430102 + (state->lane << 8))};
    need(!bind(fd, (struct sockaddr*)&address, sizeof(address)), "delivery output source bind");
    struct ip_mreqn interface = {.imr_ifindex = (int)state->index};
    need(!setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &interface, sizeof(interface)),
         "delivery output interface");
    int loop = 0;
    need(!setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)),
         "delivery output suppresses local copy");
    return fd;
}

static void include(struct delivery* state, unsigned stage, unsigned slot) {
    struct ip_mreq_source request = {.imr_multiaddr.s_addr = htonl(group),
                                     .imr_interface.s_addr = htonl(0x0a430102 + (state->lane << 8)),
                                     .imr_sourceaddr.s_addr = htonl(source(state->lane, 0))};
    step(state, stage, slot ? "include-raw" : "include-udp",
         setsockopt(state->fd[slot], IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &request,
                    sizeof(request)),
         0);
}

static void exclude(struct delivery* state, unsigned slot) {
    struct ip_mreqn group_request = {.imr_multiaddr.s_addr = htonl(group),
                                     .imr_ifindex = (int)state->index};
    step(state, 1, slot == 1 ? "exclude-udp-join" : "exclude-raw-join",
         setsockopt(state->fd[slot], IPPROTO_IP, IP_ADD_MEMBERSHIP, &group_request,
                    sizeof(group_request)),
         0);
    struct ip_mreq_source request = {.imr_multiaddr.s_addr = htonl(group),
                                     .imr_interface.s_addr = htonl(0x0a430102 + (state->lane << 8)),
                                     .imr_sourceaddr.s_addr = htonl(source(state->lane, 0))};
    step(state, 1, slot == 1 ? "exclude-udp-block" : "exclude-raw-block",
         setsockopt(state->fd[slot], IPPROTO_IP, IP_BLOCK_SOURCE, &request, sizeof(request)), 0);
}

static void action(struct delivery* state, unsigned stage) {
    if (stage == 1) {
        include(state, stage, 0);
        include(state, stage, 4);
        exclude(state, 1);
        exclude(state, 5);
        state->alias[0] = step(state, stage, "duplicate-udp", dup(state->fd[0]), 1);
        state->alias[1] = step(state, stage, "duplicate-raw", dup(state->fd[4]), 1);
    } else if (stage == 2) {
        step(state, stage, "close-original-udp", close(state->fd[0]), 0);
        step(state, stage, "close-original-raw", close(state->fd[4]), 0);
        state->fd[0] = state->alias[0];
        state->fd[4] = state->alias[1];
        state->alias[0] = state->alias[1] = -1;
    } else if (stage == 3 || stage == 4) {
        unsigned slot = stage == 3 ? 0 : 4;
        step(state, stage, slot ? "final-close-raw" : "final-close-udp", close(state->fd[slot]), 0);
        state->fd[slot] =
            step(state, stage, slot ? "fresh-raw" : "fresh-udp", receiver(state, slot), 1);
    } else if (stage == 5 || stage == 6) {
        include(state, stage, stage == 5 ? 0 : 4);
    } else if (stage == 7) {
        for (unsigned slot = 2; slot <= 6; slot += 4) {
            int value = 0;
            step(state, stage, slot == 2 ? "all-zero-udp" : "all-zero-raw",
                 setsockopt(state->fd[slot], IPPROTO_IP, IP_MULTICAST_ALL, &value, sizeof(value)),
                 0);
            all(state->fd[slot], 0);
        }
    } else {
        const unsigned slots[] = {0, 1, 4, 5};
        const char* names[] = {"leave-include-udp", "leave-exclude-udp", "leave-include-raw",
                               "leave-exclude-raw"};
        for (unsigned n = 0; n < 4; n++) {
            unsigned slot = slots[n];
            step(state, stage, names[n], close(state->fd[slot]), 0);
            state->fd[slot] = -1;
        }
        for (unsigned slot = 2; slot <= 6; slot += 4) {
            int value = 1;
            step(state, stage, slot == 2 ? "all-one-udp" : "all-one-raw",
                 setsockopt(state->fd[slot], IPPROTO_IP, IP_MULTICAST_ALL, &value, sizeof(value)),
                 0);
            all(state->fd[slot], 1);
        }
    }
}

static void output(struct delivery* state, unsigned stage) {
    struct sockaddr_in target = {
        .sin_family = AF_INET, .sin_port = htons(39901), .sin_addr.s_addr = htonl(group)};
    for (unsigned raw = 0; raw < 2; raw++) {
        unsigned char bytes[16] = {0xa0, 0x29, 0x9b, 0xdd, 0, 16, 0, 0,
                                   'A',  'X',  'S',  'O',  0, 0,  0, 0x7e};
        bytes[12] = state->lane;
        bytes[13] = stage;
        bytes[14] = raw ? 'R' : 'U';
        unsigned offset = raw ? 0 : 8, count = raw ? 16 : 8;
        unsigned long long begin = now();
        errno = 0;
        ssize_t result = sendto(state->sender[raw], bytes + offset, count, 0,
                                (struct sockaddr*)&target, sizeof(target));
        int error = result < 0 ? errno : 0;
        printf("{\"kind\":\"delivery-send\",\"lane\":%u,\"stage\":%u,\"raw\":%u,"
               "\"returncode\":%zd,\"errno\":%d,\"begin_ns\":%llu,\"end_ns\":%llu}\n",
               state->lane, stage, raw, result, error, begin, now());
        need(result == count && !error, "actual multicast output");
        sends++;
    }
}

static void input(struct delivery* state, unsigned stage, unsigned slot, unsigned seen[8],
                  const unsigned expected[8], unsigned* remaining) {
    for (;;) {
        unsigned char bytes[128];
        struct sockaddr_in origin = {0};
        socklen_t length = sizeof(origin);
        errno = 0;
        ssize_t count = recvfrom(state->fd[slot], bytes, sizeof(bytes), MSG_DONTWAIT,
                                 (struct sockaddr*)&origin, &length);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;
        int raw = slot >= 4;
        need(count == (raw ? 36 : 8) && length == sizeof(origin) && origin.sin_family == AF_INET &&
                 origin.sin_port == (raw ? 0 : htons(41002)),
             "complete delivery datagram and source metadata");
        uint32_t address = ntohl(origin.sin_addr.s_addr);
        unsigned which = address == source(state->lane, 0) ? 0 : 1;
        need(address == source(state->lane, which), "delivery source interface identity");
        if (raw) {
            need(bytes[0] == 0x45 && !bytes[1] && get16(bytes + 2) == 36 && !get16(bytes + 6) &&
                     bytes[8] == 1 && bytes[9] == 17 && !checksum(bytes, 20) &&
                     get32(bytes + 12) == address && get32(bytes + 16) == group &&
                     get16(bytes + 20) == 41002 && get16(bytes + 22) == 39901 &&
                     get16(bytes + 24) == 16 && get16(bytes + 26),
                 "complete original raw IPv4 and UDP bytes");
        }
        unsigned char payload[] = {'A',
                                   'X',
                                   'S',
                                   'I',
                                   (unsigned char)state->lane,
                                   (unsigned char)stage,
                                   (unsigned char)which,
                                   0x7e};
        need(!memcmp(bytes + (raw ? 28 : 0), payload, sizeof(payload)),
             "exact source-filtered payload");
        printf("{\"kind\":\"delivery-data\",\"lane\":%u,\"stage\":%u,\"slot\":%u,"
               "\"source\":%u,\"source_port\":%u,\"bytes\":%zd,\"hex\":\"",
               state->lane, stage, slot, address, ntohs(origin.sin_port), count);
        for (ssize_t n = 0; n < count; n++)
            printf("%02x", bytes[n]);
        puts("\"}");
        need((expected[slot] & (1U << which)) && !(seen[slot] & (1U << which)),
             "source filter and independent queue delivery");
        seen[slot] |= 1U << which;
        need(*remaining > 0, "bounded delivery count");
        --*remaining;
        received++;
    }
}

static void observe(struct delivery* state, unsigned stage) {
    static const unsigned masks[8][2] = {{85, 102}, {85, 102}, {84, 102}, {0, 102},
                                         {69, 102}, {85, 102}, {17, 34},  {0, 0}};
    unsigned expected[8], seen[8] = {0}, remaining = 0;
    struct pollfd pollers[8];
    for (unsigned slot = 0; slot < 8; slot++) {
        expected[slot] =
            ((masks[stage - 1][0] >> slot) & 1) | (((masks[stage - 1][1] >> slot) & 1) << 1);
        remaining += __builtin_popcount(expected[slot]);
        pollers[slot] = (struct pollfd){.fd = state->fd[slot], .events = POLLIN};
    }
    unsigned count = remaining;
    while (remaining) {
        need(poll(pollers, 8, 1000) > 0, "source-filtered packet receive deadline");
        for (unsigned slot = 0; slot < 8; slot++)
            need(!(pollers[slot].revents & ~POLLIN), "delivery receive poll events");
        for (unsigned slot = 0; slot < 8; slot++)
            if (state->fd[slot] >= 0)
                input(state, stage, slot, seen, expected, &remaining);
    }
    unsigned long long begin = now(), end = begin;
    while (end - begin < 200000000ULL) {
        int wait = (int)((200000000ULL - (end - begin) + 999999) / 1000000);
        int result = poll(pollers, 8, wait);
        need(result >= 0, "source delivery quiet poll");
        for (unsigned slot = 0; slot < 8; slot++)
            need(!(pollers[slot].revents & ~POLLIN), "delivery quiet poll events");
        if (result)
            for (unsigned slot = 0; slot < 8; slot++)
                if (state->fd[slot] >= 0)
                    input(state, stage, slot, seen, expected, &remaining);
        end = now();
    }
    for (unsigned slot = 0; slot < 8; slot++)
        need(seen[slot] == expected[slot], "complete source delivery mask");
    printf("{\"kind\":\"delivery-phase\",\"lane\":%u,\"stage\":%u,\"mask_a\":%u,"
           "\"mask_b\":%u,\"received\":%u,\"quiet_begin_ns\":%llu,\"quiet_end_ns\":%llu}\n",
           state->lane, stage, masks[stage - 1][0], masks[stage - 1][1], count, begin, end);
}

void ipv4_source_delivery(const unsigned indices[2], void (*barrier)(unsigned, int)) {
    struct delivery states[2];
    for (unsigned lane = 0; lane < 2; lane++) {
        struct delivery* state = &states[lane];
        *state = (struct delivery){.lane = lane, .index = indices[lane], .alias = {-1, -1}};
        for (unsigned slot = 0; slot < 8; slot++)
            state->fd[slot] = receiver(state, slot);
        state->sender[0] = sender(state, 0);
        state->sender[1] = sender(state, 1);
    }
    for (unsigned stage = 1; stage <= 8; stage++) {
        barrier(stage, 0);
        for (unsigned lane = 0; lane < 2; lane++) {
            action(&states[lane], stage);
            output(&states[lane], stage);
        }
        unsigned long long begin = now();
        barrier(stage, 1);
        printf("{\"kind\":\"observation\",\"stage\":%u,\"begin_ns\":%llu,\"end_ns\":%llu}\n", stage,
               begin, now());
        for (unsigned lane = 0; lane < 2; lane++)
            observe(&states[lane], stage);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned slot = 0; slot < 8; slot++)
            if (states[lane].fd[slot] >= 0)
                need(!close(states[lane].fd[slot]), "delivery receiver final close");
        need(!close(states[lane].sender[0]) && !close(states[lane].sender[1]),
             "delivery sender final close");
    }
    need(actions == 48 && sends == 32 && received == 92, "complete delivery execution inventory");
}

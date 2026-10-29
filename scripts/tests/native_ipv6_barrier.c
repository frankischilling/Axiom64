// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void need(int okay, const char* text) {
    if (!okay) {
        fprintf(stderr, "BARRIER_CLIENT_FAIL %s errno=%d\n", text, errno);
        exit(1);
    }
}

int main(int argc, char** argv) {
    need(argc == 2, "case count");
    unsigned count = (unsigned)strtoul(argv[1], NULL, 10);
    need(count && count <= 65536, "bounded cases");
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(3));
    unsigned index = if_nametoindex("eth0");
    struct sockaddr_ll address = {.sll_family = AF_PACKET,
                                  .sll_protocol = htons(3),
                                  .sll_ifindex = (int)index,
                                  .sll_halen = 6};
    unsigned char request[60] = {2,    0x49, 0x50, 0x36, 0,    0,   0x52, 0x54, 0,
                                 0x12, 0x34, 0x10, 0x88, 0xf1, 'A', 'X',  'C',  'O'};
    memcpy(address.sll_addr, request, 6);
    need(fd >= 0 && index && !bind(fd, (void*)&address, sizeof(address)),
         "real packet description");
    address.sll_protocol = htons(0x88f1);
    for (unsigned sequence = 0; sequence < count; sequence++) {
        uint32_t encoded = htonl(sequence);
        memcpy(request + 20, &encoded, sizeof(encoded));
        need(sendto(fd, request, sizeof(request), 0, (void*)&address, sizeof(address)) == 60,
             "original barrier request");
        struct pollfd ready = {.fd = fd, .events = POLLIN};
        need(poll(&ready, 1, 5000) == 1 && ready.revents & POLLIN,
             "five-second original readiness");
        unsigned char response[61], expected[60];
        memcpy(expected, request, sizeof(expected));
        memcpy(expected, request + 6, 6);
        memcpy(expected + 6, request, 6);
        expected[18] = 1;
        need(recv(fd, response, sizeof(response), 0) == 60 && !memcmp(response, expected, 60),
             "owned acknowledgment before next request");
    }
    cpu_set_t mask;
    need(!sched_getaffinity(0, sizeof(mask), &mask), "actual client affinity");
    printf("BARRIER_CLIENT_PASS cases=%u cpu_count=%d\n", count, CPU_COUNT(&mask));
    need(!close(fd), "close owned description");
    return 0;
}

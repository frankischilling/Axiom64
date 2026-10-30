// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "raw_header_queue.h"
#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <net/if.h>
#include <net/route.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned current_lane, current_case;

static void require(int okay, const char* label) {
    if (!okay) {
        fprintf(stderr, "IPV4_RAW_QUEUE_FAIL index=%u test=%u label=%s errno=%d uid=%u\n",
                current_lane + 1, current_case, label, errno, geteuid());
        exit(1);
    }
}

static uint64_t monotonic(void) {
    struct timespec value;
    require(clock_gettime(CLOCK_MONOTONIC, &value) == 0, "clock");
    return (uint64_t)value.tv_sec * 1000000000 + (uint64_t)value.tv_nsec;
}

static void address(int fd, const char* name, uint32_t value, uint32_t mask) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    struct sockaddr_in* selected = (struct sockaddr_in*)&request.ifr_addr;
    selected->sin_family = AF_INET;
    selected->sin_addr.s_addr = htonl(value);
    require(ioctl(fd, SIOCSIFADDR, &request) == 0, "address");
    if (value) {
        selected->sin_addr.s_addr = htonl(mask);
        require(ioctl(fd, SIOCSIFNETMASK, &request) == 0, "mask");
    }
}

static void host_route(int fd, const char* name, uint32_t target, int remove) {
    struct rtentry route = {0};
    struct sockaddr_in* destination = (struct sockaddr_in*)&route.rt_dst;
    struct sockaddr_in* mask = (struct sockaddr_in*)&route.rt_genmask;
    struct sockaddr_in* gateway = (struct sockaddr_in*)&route.rt_gateway;
    destination->sin_family = mask->sin_family = gateway->sin_family = AF_INET;
    destination->sin_addr.s_addr = htonl(target);
    mask->sin_addr.s_addr = htonl(UINT32_MAX);
    route.rt_flags = RTF_UP | RTF_HOST;
    route.rt_dev = (char*)name;
    require(ioctl(fd, remove ? SIOCDELRT : SIOCADDRT, &route) == 0, "host-route");
}

static void exchange(int fd, int index, const unsigned char mac[6], unsigned test, unsigned phase) {
    unsigned char frame[60] = {0};
    const unsigned char peer[6] = {2, 0x41, 0x58, 0x49, 0x50, (unsigned char)current_lane};
    memcpy(frame, peer, 6);
    memcpy(frame + 6, mac, 6);
    frame[12] = 0x88;
    frame[13] = 0xb5;
    memcpy(frame + 14, "RHQ1", 4);
    frame[18] = (unsigned char)current_lane;
    frame[19] = (unsigned char)test;
    frame[20] = (unsigned char)phase;
    for (unsigned at = 21; at < sizeof(frame); at++)
        frame[at] = (unsigned char)(at * 19 + test * 11 + current_lane * 31);
    struct sockaddr_ll destination = {.sll_family = AF_PACKET,
                                      .sll_protocol = htons(0x88b5),
                                      .sll_ifindex = index,
                                      .sll_halen = 6};
    memcpy(destination.sll_addr, peer, 6);
    uint64_t began = monotonic();
    require(sendto(fd, frame, sizeof(frame), 0, (struct sockaddr*)&destination,
                   sizeof(destination)) == sizeof(frame),
            "control-send");
    unsigned char expected[60];
    memcpy(expected, frame, sizeof(expected));
    memcpy(expected, mac, 6);
    memcpy(expected + 6, peer, 6);
    expected[21] ^= 0x80;
    const uint64_t deadline = began + 5000000000ULL;
    for (;;) {
        uint64_t now = monotonic();
        if (now >= deadline) {
            errno = ETIMEDOUT;
            require(0, "control-deadline");
        }
        struct pollfd event = {.fd = fd, .events = POLLIN};
        int ready = poll(&event, 1, (int)((deadline - now + 999999) / 1000000));
        require(ready >= 0, "control-poll");
        if (!ready)
            continue;
        require(event.revents & POLLIN, "control-readiness");
        unsigned char received[128];
        ssize_t count = recv(fd, received, sizeof(received), MSG_TRUNC);
        require(count >= 14 && count <= (ssize_t)sizeof(received), "control-framing");
        // Native packet sockets can observe their own outgoing control frame.
        if (!memcmp(received + 6, mac, 6))
            continue;
        require(count == sizeof(expected) && !memcmp(received, expected, sizeof(expected)),
                "complete-control-acknowledgement");
        require(monotonic() - began <= 5000000000ULL, "control-elapsed");
        return;
    }
}

void ipv4_raw_header_queue_checks(unsigned lane, int selected_case) {
    current_lane = lane;
    current_case = 0;
    require(lane < 2 && selected_case >= -1 && selected_case < 6 && geteuid() == 0, "fixture");
    const char* name = lane ? "eth1" : "eth0";
    const char* alias = lane ? "eth1:rhq" : "eth0:rhq";
    uint32_t local = 0x0a170002u + (lane + 1) * 256;
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(control >= 0, "configuration-socket");
    struct ifreq info = {0};
    snprintf(info.ifr_name, sizeof(info.ifr_name), "%s", name);
    require(ioctl(control, SIOCGIFINDEX, &info) == 0, "interface-index");
    int index = info.ifr_ifindex;
    require(ioctl(control, SIOCGIFHWADDR, &info) == 0, "interface-hardware");
    unsigned char mac[6];
    memcpy(mac, info.ifr_hwaddr.sa_data, 6);
    require(ioctl(control, SIOCGIFFLAGS, &info) == 0, "interface-flags");
    info.ifr_flags |= IFF_UP;
    require(ioctl(control, SIOCSIFFLAGS, &info) == 0, "interface-up");
    int link = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(0x88b5));
    struct sockaddr_ll binding = {
        .sll_family = AF_PACKET, .sll_protocol = htons(0x88b5), .sll_ifindex = index};
    require(link >= 0 && bind(link, (struct sockaddr*)&binding, sizeof(binding)) == 0,
            "control-binding");
    unsigned completed = 0;
    for (unsigned test = 0; test < 6; test++) {
        if (selected_case >= 0 && test != (unsigned)selected_case)
            continue;
        current_case = test;
        address(control, name, local, 0xffffff00);
        address(control, alias, local + 1, UINT32_MAX);
        info.ifr_mtu = 1500;
        require(ioctl(control, SIOCSIFMTU, &info) == 0, "initial-mtu");
        uint32_t target = (local & 0xffffff00u) + 200 + test;
        if (test == 2)
            host_route(control, name, target, 0);
        int raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
        require(raw >= 0 &&
                    setsockopt(raw, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
                "raw-description");
        size_t length = test == 1 ? 1500 : 28;
        unsigned char bytes[1500] = {0x45,
                                     0x5a,
                                     0x11,
                                     0x11,
                                     0x13,
                                     0x57,
                                     0,
                                     0,
                                     35,
                                     76,
                                     0xaa,
                                     0xaa,
                                     192,
                                     0,
                                     2,
                                     1,
                                     10,
                                     23,
                                     (unsigned char)(lane + 1),
                                     77};
        for (size_t at = 20; at < length; at++)
            bytes[at] = (unsigned char)(at * 37 + test * 11 + lane * 31);
        struct sockaddr_in destination = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(target)};
        exchange(link, index, mac, test, 0);
        if (test == 5) {
            pid_t child = fork();
            require(child >= 0, "ordinary-fork");
            if (!child) {
                require(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0,
                        "ordinary-credentials");
                require(sendto(raw, bytes, length, 0, (struct sockaddr*)&destination,
                               sizeof(destination)) == (ssize_t)length,
                        "ordinary-accepted-send");
                memset(bytes, 0xcc, length);
                _exit(0);
            }
            int status;
            require(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                        WEXITSTATUS(status) == 0,
                    "ordinary-completion");
        } else
            require(sendto(raw, bytes, length, 0, (struct sockaddr*)&destination,
                           sizeof(destination)) == (ssize_t)length,
                    "accepted-send");
        exchange(link, index, mac, test, 1); // The peer holds the actual ARP request.
        if (test == 0) {
            address(control, name, 0, 0);
            struct ifreq surviving = {0};
            snprintf(surviving.ifr_name, sizeof(surviving.ifr_name), "%s", alias);
            require(ioctl(control, SIOCGIFADDR, &surviving) == 0 &&
                        ((struct sockaddr_in*)&surviving.ifr_addr)->sin_addr.s_addr ==
                            htonl(local + 1),
                    "surviving-address");
        } else if (test == 1) {
            info.ifr_mtu = 68;
            require(ioctl(control, SIOCSIFMTU, &info) == 0, "reduced-mtu");
            require(ioctl(control, SIOCGIFMTU, &info) == 0 && info.ifr_mtu == 68,
                    "observed-reduced-mtu");
            errno = 0;
            require(sendto(raw, bytes, length, 0, (struct sockaddr*)&destination,
                           sizeof(destination)) == -1 &&
                        errno == EMSGSIZE,
                    "fresh-send-rejects-reduced-mtu");
        } else if (test == 2)
            host_route(control, name, target, 1);
        else if (test == 3)
            require(close(raw) == 0, "last-close");
        else {
            int disabled = 0;
            require(setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &disabled, 4) == 0 &&
                        setsockopt(raw, IPPROTO_IP, IP_OPTIONS, NULL, 0) == 0,
                    "changed-description");
            int observed = -1;
            socklen_t size = sizeof(observed);
            require(getsockopt(raw, IPPROTO_IP, IP_HDRINCL, &observed, &size) == 0 &&
                        size == sizeof(observed) && observed == 0,
                    "observed-changed-description");
        }
        memset(bytes, 0xcc, length);
        exchange(link, index, mac, test, 2); // ACK follows the exact retained packet.
        if (test != 3)
            require(close(raw) == 0, "data-close");
        address(control, name, local, 0xffffff00);
        address(control, alias, 0, 0);
        info.ifr_mtu = 1500;
        require(ioctl(control, SIOCSIFMTU, &info) == 0, "restored-mtu");
        completed++;
        printf("IPV4_RAW_QUEUE_CASE_PASS index=%u test=%u bytes=%zu ordinary=%u\n", lane + 1, test,
               length, test == 5);
    }
    exchange(link, index, mac, 6, 0);
    require(close(link) == 0 && close(control) == 0, "close-controls");
    printf("IPV4_RAW_QUEUE_PASS index=%u cases=%u selected=%d\n", lane + 1, completed,
           selected_case);
}

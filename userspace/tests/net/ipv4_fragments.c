// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_fragments.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void require(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "IPV4_FRAGMENT_FAIL %s errno=%d\n", label, errno);
        exit(1);
    }
}

static unsigned sum(const unsigned char* bytes, size_t length) {
    unsigned result = 0;
    while (length >= 2) {
        result += (unsigned)bytes[0] * 256 + bytes[1];
        bytes += 2;
        length -= 2;
    }
    if (length)
        result += (unsigned)bytes[0] * 256;
    while (result >> 16)
        result = (result & 65535) + (result >> 16);
    return (~result) & 65535;
}

static double elapsed(void) {
    struct timespec value;
    require(clock_gettime(CLOCK_MONOTONIC, &value) == 0, "monotonic clock");
    return value.tv_sec + value.tv_nsec / 1e9;
}

static void configure(int fd, unsigned lane, const char* name) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    struct sockaddr_in* address = (struct sockaddr_in*)&request.ifr_addr;
    char text[32];
    snprintf(text, sizeof(text), "10.23.%u.2", lane + 1);
    address->sin_family = AF_INET;
    require(inet_pton(AF_INET, text, &address->sin_addr) == 1, "local address parse");
    require(ioctl(fd, SIOCSIFADDR, &request) == 0, "local address");
    require(inet_pton(AF_INET, "255.255.255.0", &address->sin_addr) == 1, "netmask parse");
    require(ioctl(fd, SIOCSIFNETMASK, &request) == 0, "netmask");
    require(ioctl(fd, SIOCGIFFLAGS, &request) == 0, "read flags");
    request.ifr_flags |= IFF_UP;
    require(ioctl(fd, SIOCSIFFLAGS, &request) == 0, "enable interface");
}

static void send_control(int fd, const struct sockaddr_in* peer, unsigned lane, const char tag[2],
                         unsigned test, unsigned phase) {
    unsigned char bytes[32] = {8, 0, 0, 0, tag[0], tag[1], test, phase};
    for (unsigned i = 8; i < sizeof(bytes); i++)
        bytes[i] = (unsigned char)(i * 17 + lane * 31);
    unsigned checksum = sum(bytes, sizeof(bytes));
    bytes[2] = checksum >> 8;
    bytes[3] = checksum;
    require(sendto(fd, bytes, sizeof(bytes), 0, (const struct sockaddr*)peer, sizeof(*peer)) ==
                sizeof(bytes),
            "control send");
}

static void control(int fd, const struct sockaddr_in* peer, unsigned lane, unsigned test,
                    unsigned phase) {
    send_control(fd, peer, lane, "FR", test, phase);
}

static void receive_packet(int fd, unsigned lane, unsigned test, int barrier) {
    unsigned char* bytes = malloc(65535);
    require(bytes != NULL, "receive allocation");
    double deadline = elapsed() + 5;
    for (;;) {
        double left = deadline - elapsed();
        require(left > 0, "receive deadline");
        struct pollfd event = {fd, POLLIN, 0};
        require(poll(&event, 1, (int)(left * 1000) + 1) > 0 && (event.revents & POLLIN),
                "receive readiness");
        ssize_t length = recv(fd, bytes, 65535, 0);
        require(length >= 28 && bytes[0] == 0x45 && bytes[9] == IPPROTO_ICMP &&
                    ((unsigned)bytes[2] * 256 + bytes[3]) == (unsigned)length &&
                    sum(bytes, 20) == 0 && sum(bytes + 20, length - 20) == 0,
                "complete header and ICMP checksum");
        require(bytes[12] == 10 && bytes[13] == 23 && bytes[14] == lane + 1 && bytes[15] == 1 &&
                    bytes[16] == 10 && bytes[17] == 23 && bytes[18] == lane + 1 && bytes[19] == 2,
                "wire source and local destination");
        if (bytes[20] != 0 || bytes[21] || bytes[24] != 'F')
            continue;
        if (barrier) {
            require(length == 28 && bytes[25] == 'B' && bytes[26] == test && bytes[27] == lane,
                    "ordered barrier without delivery of rejected or incomplete data");
        } else {
            size_t payload = test == 5 ? 65515 : test == 1 ? 65 : 64;
            require(length == (ssize_t)(20 + payload) && bytes[25] == 'R' && bytes[26] == test &&
                        bytes[27] == lane && !(bytes[6] & 0x3f) && !bytes[7],
                    "reassembled length, identity and fragment bits");
            for (size_t i = 8; i < payload; i++)
                require(bytes[20 + i] == (unsigned char)(i * 17 + lane * 31 + test),
                        "every reassembled payload byte");
        }
        break;
    }
    free(bytes);
}

static void output_control(int fd, const struct sockaddr_in* peer, unsigned lane, unsigned test,
                           unsigned phase) {
    send_control(fd, peer, lane, "FO", test, phase);
}

static void acknowledgement(int fd, unsigned lane, const char tag[2], unsigned test, unsigned phase,
                            int timeout) {
    struct pollfd event = {fd, POLLIN, 0};
    int ready = poll(&event, 1, timeout);
    if (ready != 1 || !(event.revents & POLLIN)) {
        int failure = ready < 0 ? errno : ready == 0 ? ETIMEDOUT : EIO;
        fprintf(stderr,
                "IPV4_FRAGMENT_ACK_FAIL index=%u tag=%c%c test=%u phase=%u timeout_ms=%d "
                "poll=%d revents=%x errno=%d\n",
                lane + 1, tag[0], tag[1], test, phase, timeout, ready,
                (unsigned short)event.revents, failure);
        errno = failure;
        require(0, "output acknowledgement readiness");
    }
    unsigned char bytes[52];
    require(recv(fd, bytes, sizeof(bytes), MSG_TRUNC) == sizeof(bytes) && bytes[0] == 0x45 &&
                bytes[9] == IPPROTO_ICMP && bytes[20] == 0 && bytes[21] == 0 &&
                bytes[24] == tag[0] && bytes[25] == tag[1] && bytes[26] == test &&
                bytes[27] == phase && bytes[12] == 10 && bytes[13] == 23 && bytes[14] == lane + 1 &&
                bytes[15] == 1 && bytes[16] == 10 && bytes[17] == 23 && bytes[18] == lane + 1 &&
                bytes[19] == 2 && sum(bytes, 20) == 0 && sum(bytes + 20, 32) == 0,
            "output acknowledgement bytes");
    for (unsigned i = 8; i < 32; i++)
        require(bytes[20 + i] == (unsigned char)(i * 17 + lane * 31),
                "output acknowledgement body");
}

static void output_acknowledgement(int fd, unsigned lane, unsigned test, unsigned phase) {
    acknowledgement(fd, lane, "FO", test, phase, 5000);
}

static void output_checks(unsigned lane, const char* name, const struct sockaddr_in* peer) {
    const struct {
        int udp, policy, mtu;
        size_t length;
    } cases[] = {{0, 0, 1500, 65515}, {0, 1, 1500, 65515}, {1, 0, 1500, 65507}, {1, 1, 1500, 65507},
                 {0, 2, 1500, 1481},  {0, 3, 1500, 1481},  {1, 2, 1500, 1473},  {1, 3, 1500, 1473},
                 {0, 0, 68, 4096},    {1, 1, 68, 4096},    {0, 1, 1500, 1480},  {1, 0, 1500, 1472},
                 {0, 1, 1500, 1481},  {1, 1, 1500, 1473},  {0, 0, 68, 65515},   {0, 4, 1500, 1481},
                 {1, 4, 1500, 1473},  {0, 5, 1500, 65515}, {1, 5, 1500, 65507}, {0, 4, 1500, 1480},
                 {1, 4, 1500, 1472}};

    int control_fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    int raw = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(control_fd >= 0 && raw >= 0 && udp >= 0, "output sockets");
    int descriptors[] = {control_fd, raw, udp};
    for (unsigned i = 0; i < 3; i++)
        require(setsockopt(descriptors[i], SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) ==
                    0,
                "output device binding");
    // Minimum-MTU raw packets need room for Linux's per-fragment socket charges.
    // This raises only a privileged socket quota; the guest output table stays bounded.
    int quota = 4 * 1024 * 1024;
    require(setsockopt(raw, SOL_SOCKET, SO_SNDBUFFORCE, &quota, sizeof(quota)) == 0,
            "privileged fragmented send quota");
    int actual = 0;
    socklen_t quota_length = sizeof(actual);
    require(getsockopt(raw, SOL_SOCKET, SO_SNDBUF, &actual, &quota_length) == 0 &&
                actual == quota * 2 && quota_length == sizeof(actual),
            "privileged quota readback");
    pid_t child = fork();
    require(child >= 0, "quota capability child");
    if (!child) {
        if (setuid(65534) != 0)
            _exit(1);
        _exit(setsockopt(raw, SOL_SOCKET, SO_SNDBUFFORCE, &quota, sizeof(quota)) == -1 &&
                      errno == EPERM
                  ? 0
                  : 1);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
            "unprivileged quota override denied");
    unsigned filter = ~1u;
    require(setsockopt(control_fd, 255, 1, &filter, sizeof(filter)) == 0, "output control filter");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(45000 + lane)};
    require(bind(udp, (struct sockaddr*)&local, sizeof(local)) == 0, "output UDP source port");
    unsigned char* bytes = malloc(65515);
    require(bytes != NULL, "output payload allocation");
    for (unsigned test = 0; test < sizeof(cases) / sizeof(cases[0]); test++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
        request.ifr_mtu = cases[test].mtu;
        require(ioctl(control_fd, SIOCSIFMTU, &request) == 0, "output interface MTU");
        int fd = cases[test].udp ? udp : raw;
        require(setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &cases[test].policy,
                           sizeof(cases[test].policy)) == 0,
                "output discovery policy");
        output_control(control_fd, peer, lane, test, 0);
        output_acknowledgement(control_fd, lane, test, 0);
        size_t length = cases[test].length;
        memset(bytes, 0, 8);
        bytes[0] = 8;
        bytes[4] = 'F';
        bytes[5] = 'D';
        bytes[6] = test;
        bytes[7] = lane;
        for (size_t i = 8; i < length; i++)
            bytes[i] = (unsigned char)(i * 17 + lane * 31 + test);
        unsigned checksum = sum(bytes, length);
        bytes[2] = checksum >> 8;
        bytes[3] = checksum;
        struct sockaddr_in destination = *peer;
        destination.sin_port = cases[test].udp ? htons(24000 + lane) : 0;
        ssize_t sent =
            sendto(fd, bytes, length, 0, (struct sockaddr*)&destination, sizeof(destination));
        if (cases[test].policy >= 2 && cases[test].policy <= 4 &&
            cases[test].length + (cases[test].udp ? 28 : 20) > (size_t)cases[test].mtu) {
            require(sent == -1 && errno == EMSGSIZE, "DF rejects oversized output");
            output_control(control_fd, peer, lane, test, 1);
        } else
            require(sent == (ssize_t)length, "complete output datagram accepted");
        // The queued datagram must retain every byte after the syscall returns.
        memset(bytes, 0xa5, length);
        output_acknowledgement(control_fd, lane, test, 1);
        printf("IPV4_FRAGMENT_OUTPUT_CASE index=%u test=%u\n", lane + 1, test);
    }
    struct ifreq restore = {0};
    snprintf(restore.ifr_name, sizeof(restore.ifr_name), "%s", name);
    restore.ifr_mtu = 1500;
    require(ioctl(control_fd, SIOCSIFMTU, &restore) == 0, "restore output MTU");
    output_control(control_fd, peer, lane, 21, 0);
    free(bytes);
    require(close(control_fd) == 0 && close(raw) == 0 && close(udp) == 0, "output socket close");
    printf("IPV4_FRAGMENT_OUTPUT_PASS index=%u cases=21\n", lane + 1);
}

void ipv4_fragment_checks(unsigned lane) {
    require(lane < 2, "lane bound");
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    require(fd >= 0, "raw socket");
    char name[IFNAMSIZ], text[32];
    snprintf(name, sizeof(name), "eth%u", lane);
    configure(fd, lane, name);
    require(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
            "receive device binding");
    unsigned filter = ~1u;
    require(setsockopt(fd, 255, 1, &filter, sizeof(filter)) == 0, "echo-reply filter");
    struct sockaddr_in peer = {.sin_family = AF_INET};
    snprintf(text, sizeof(text), "10.23.%u.1", lane + 1);
    require(inet_pton(AF_INET, text, &peer.sin_addr) == 1, "peer address parse");
    for (unsigned test = 0; test < 6; test++) {
        control(fd, &peer, lane, test, 0);
        if (test >= 2 && test <= 4) {
            receive_packet(fd, lane, test, 1);
            control(fd, &peer, lane, test, 1);
        }
        receive_packet(fd, lane, test, 0);
        if (test == 4)
            receive_packet(fd, lane, test, 1);
    }
    control(fd, &peer, lane, 6, 0);
    require(close(fd) == 0, "raw socket close");
    printf("IPV4_FRAGMENT_PASS index=%u cases=6\n", lane + 1);
    output_checks(lane, name, &peer);
}

void ipv4_fragment_expiry_checks(void) {
    int sockets[2];
    struct sockaddr_in peers[2];
    double started[2];
    // Both queues age concurrently; neither kernel clock nor queue deadline changes.
    for (unsigned lane = 0; lane < 2; lane++) {
        sockets[lane] = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
        require(sockets[lane] >= 0, "expiry raw socket");
        char name[IFNAMSIZ], address[32];
        snprintf(name, sizeof(name), "eth%u", lane);
        configure(sockets[lane], lane, name);
        require(setsockopt(sockets[lane], SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
                "expiry device binding");
        unsigned filter = ~1u;
        require(setsockopt(sockets[lane], 255, 1, &filter, sizeof(filter)) == 0,
                "expiry reply filter");
        memset(&peers[lane], 0, sizeof(peers[lane]));
        peers[lane].sin_family = AF_INET;
        snprintf(address, sizeof(address), "10.23.%u.1", lane + 1);
        require(inet_pton(AF_INET, address, &peers[lane].sin_addr) == 1, "expiry peer parse");
        started[lane] = elapsed();
        send_control(sockets[lane], &peers[lane], lane, "FE", lane, 0);
        acknowledgement(sockets[lane], lane, "FE", lane, 0, 5000);
        printf("IPV4_FRAGMENT_EXPIRY_STARTED index=%u monotonic=%.9f\n", lane + 1, started[lane]);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        acknowledgement(sockets[lane], lane, "FE", lane, 1, 100000);
        double duration = elapsed() - started[lane];
        require(duration >= 60 && duration <= 100, "real elapsed expiry observation");
        // A last fragment alone must not complete using any expired first bytes.
        send_control(sockets[lane], &peers[lane], lane, "FE", lane, 2);
        acknowledgement(sockets[lane], lane, "FE", lane, 2, 5000);
        send_control(sockets[lane], &peers[lane], lane, "FE", lane, 3);
        struct pollfd ready = {sockets[lane], POLLIN, 0};
        require(poll(&ready, 1, 5000) == 1 && (ready.revents & POLLIN),
                "reused identity completion");
        unsigned char packet[84], body[64] = {0, 0, 0, 0, 'F', 'R', 0, lane};
        for (unsigned i = 8; i < sizeof(body); i++)
            body[i] = (unsigned char)(i * 17 + lane * 31);
        unsigned check = sum(body, sizeof(body));
        body[2] = check >> 8;
        body[3] = check;
        require(recv(sockets[lane], packet, sizeof(packet), MSG_TRUNC) == sizeof(packet) &&
                    packet[0] == 0x45 && packet[8] == 51 && packet[9] == 1 && packet[4] == 0x7a &&
                    packet[5] == 0x10 + lane * 16 && packet[6] == 0 && packet[7] == 0 &&
                    sum(packet, 20) == 0 && packet[12] == 10 && packet[13] == 23 &&
                    packet[14] == lane + 1 && packet[15] == 1 && packet[16] == 10 &&
                    packet[17] == 23 && packet[18] == lane + 1 && packet[19] == 2 &&
                    memcmp(packet + 20, body, sizeof(body)) == 0,
                "expired queue discards old bytes before identity reuse");
        send_control(sockets[lane], &peers[lane], lane, "FE", lane, 4);
        require(close(sockets[lane]) == 0, "expiry socket close");
        printf("IPV4_FRAGMENT_EXPIRY_PASS index=%u elapsed=%.9f\n", lane + 1, duration);
    }
}

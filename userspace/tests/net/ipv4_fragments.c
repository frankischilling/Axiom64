// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "ipv4_fragments.h"
#include "ipv4/raw_header_queue.h"
#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
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

static size_t output_options(unsigned test, unsigned char bytes[40]);
static uint64_t output_wall_milliseconds(void);

static void input_option_bytes(unsigned char* bytes, size_t header, unsigned lane, unsigned test,
                               uint64_t before, uint64_t after) {
    const unsigned selected[] = {35, 35, 36, 36, 21, 35};
    unsigned char expected[40], actual[40], original[60];
    size_t size = output_options(selected[test - 6], expected);
    require(header == 20 + size, "received option header size");
    memcpy(actual, bytes + 20, size);
    memcpy(original, bytes, header);
    for (size_t at = 0; at < size;) {
        unsigned kind = expected[at];
        if (!kind)
            break;
        if (kind == 1) {
            at++;
            continue;
        }
        unsigned length = expected[at + 1];
        if (kind == 7) {
            expected[at + 2] = 8;
            const unsigned char address[] = {10, 23, lane + 1, 2};
            memcpy(expected + at + 3, address, sizeof(address));
            original[20 + at + 2] = 4;
            memset(original + 20 + at + 3, 0, 4);
        } else if (kind == 68) {
            expected[at + 2] = 9;
            uint32_t stamp = (uint32_t)actual[at + 4] << 24 | (uint32_t)actual[at + 5] << 16 |
                             (uint32_t)actual[at + 6] << 8 | actual[at + 7];
            uint64_t delta = (stamp + 86400000 - before % 86400000 + 20) % 86400000;
            require(stamp < 86400000 && after >= before && after - before < 5000 &&
                        delta <= after - before + 40,
                    "actual received option timestamp");
            memset(actual + at + 4, 0, 4);
            original[20 + at + 2] = 5;
            memset(original + 20 + at + 4, 0, 4);
        }
        at += length;
    }
    require(!memcmp(actual, expected, size), "complete received option bytes");
    if (test == 6 || test == 8)
        require(sum(original, header) == 0,
                "unfragmented original checksum retained after options");
    else
        require(sum(bytes, header) == 0, "reassembled checksum covers already processed options");
}

static void receive_packet(int fd, unsigned lane, unsigned test, int barrier) {
    unsigned char* bytes = malloc(65535);
    require(bytes != NULL, "receive allocation");
    double deadline = elapsed() + 5;
    uint64_t before = output_wall_milliseconds();
    for (;;) {
        double left = deadline - elapsed();
        require(left > 0, "receive deadline");
        struct pollfd event = {fd, POLLIN, 0};
        require(poll(&event, 1, (int)(left * 1000) + 1) > 0 && (event.revents & POLLIN),
                "receive readiness");
        ssize_t length = recv(fd, bytes, 65535, 0);
        require(length >= 28, "complete received IPv4 prefix");
        size_t header = (bytes[0] & 15) * 4;
        require(length >= 28 && bytes[0] >> 4 == 4 && header >= 20 && header <= 60 &&
                    header + 8 <= (size_t)length && bytes[9] == IPPROTO_ICMP &&
                    ((unsigned)bytes[2] * 256 + bytes[3]) == (unsigned)length &&
                    (test >= 6 || (header == 20 && sum(bytes, header) == 0)) &&
                    sum(bytes + header, length - header) == 0,
                "complete header and ICMP checksum");
        require(bytes[12] == 10 && bytes[13] == 23 && bytes[14] == lane + 1 && bytes[15] == 1 &&
                    bytes[16] == 10 && bytes[17] == 23 && bytes[18] == lane + 1 && bytes[19] == 2,
                "wire source and local destination");
        if (bytes[header] != 0 || bytes[header + 1] || bytes[header + 4] != 'F')
            continue;
        if (barrier) {
            require(length == 28 && bytes[25] == 'B' && bytes[26] == test && bytes[27] == lane,
                    "ordered barrier without delivery of rejected or incomplete data");
        } else {
            size_t payload = test == 5 ? 65515 : test == 1 ? 65 : 64;
            require(length == (ssize_t)(header + payload) && bytes[header + 5] == 'R' &&
                        bytes[header + 6] == test && bytes[header + 7] == lane &&
                        !(bytes[6] & 0x3f) && !bytes[7],
                    "reassembled length, identity and fragment bits");
            for (size_t i = 8; i < payload; i++)
                require(bytes[header + i] == (unsigned char)(i * 17 + lane * 31 + test),
                        "every reassembled payload byte");
            if (test >= 6) {
                uint64_t after = output_wall_milliseconds();
                printf("IPV4_FRAGMENT_INPUT_OPTIONS index=%u test=%u utc_before_ms=%llu "
                       "utc_after_ms=%llu length=%zu bytes=",
                       lane + 1, test, (unsigned long long)before, (unsigned long long)after,
                       (size_t)length);
                for (size_t at = 0; at < (size_t)length; at++)
                    printf("%02x", bytes[at]);
                putchar('\n');
                input_option_bytes(bytes, header, lane, test, before, after);
            }
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

static size_t output_options(unsigned test, unsigned char bytes[40]) {
    memset(bytes, 0, 40);
    if (test < 21)
        return 0;
    unsigned kind = test <= 34                               ? 1
                    : test == 35 || test == 41 || test == 42 ? 2
                    : test == 36 || test == 39 || test == 40 ? 3
                    : test == 37                             ? 4
                    : test == 38                             ? 5
                                                             : 6;
    if (kind == 1) {
        const unsigned char mixed[] = {148, 4, 0, 0, 7, 7, 4,   0, 0,  0,  0,  1, 68, 8,
                                       5,   0, 0, 0, 0, 0, 158, 4, 18, 52, 30, 4, 86, 120};
        memcpy(bytes, mixed, sizeof(mixed));
        memset(bytes + sizeof(mixed), 1, 40 - sizeof(mixed));
        return 40;
    }
    if (kind == 2) {
        bytes[0] = 7;
        bytes[1] = 7;
        bytes[2] = 4;
        return 8;
    }
    if (kind == 3) {
        bytes[0] = 68;
        bytes[1] = 8;
        bytes[2] = 5;
        return 8;
    }
    if (kind == 4) {
        bytes[0] = 148;
        bytes[1] = 4;
        return 4;
    }
    if (kind == 5) {
        const unsigned char opaque[] = {158, 4, 170, 187, 30, 4, 204, 221};
        memcpy(bytes, opaque, sizeof(opaque));
        return sizeof(opaque);
    }
    memset(bytes, 1, 40);
    return 40;
}

static uint64_t output_wall_milliseconds(void) {
    struct timespec now;
    require(clock_gettime(CLOCK_REALTIME, &now) == 0, "output wall clock");
    return (uint64_t)now.tv_sec * 1000 + (unsigned long)now.tv_nsec / 1000000;
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
                 {1, 4, 1500, 1472},  {0, 0, 1500, 65475}, {1, 1, 1500, 65467}, {0, 0, 68, 512},
                 {1, 1, 68, 512},     {0, 2, 1500, 1441},  {1, 2, 1500, 1433},  {0, 1, 1500, 1440},
                 {1, 1, 1500, 1432},  {0, 3, 1500, 1441},  {1, 4, 1500, 1433},  {0, 5, 1500, 65475},
                 {1, 5, 1500, 65467}, {0, 0, 1500, 65476}, {1, 0, 1500, 65468}, {0, 0, 1500, 4096},
                 {1, 0, 1500, 4096},  {0, 1, 1500, 4096},  {1, 1, 1500, 4096},  {0, 0, 68, 32},
                 {1, 0, 68, 33},      {0, 2, 68, 40},      {1, 2, 68, 33},      {0, 0, 1500, 65475},
                 {1, 0, 1500, 65467}};

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
        unsigned char options[40], queried[40];
        size_t option_length = output_options(test, options);
        require(setsockopt(fd, IPPROTO_IP, IP_OPTIONS, options, (socklen_t)option_length) == 0,
                "output packet options");
        socklen_t queried_length = sizeof(queried);
        require(getsockopt(fd, IPPROTO_IP, IP_OPTIONS, queried, &queried_length) == 0 &&
                    queried_length == option_length && !memcmp(queried, options, option_length),
                "output normalized options query");
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
        uint64_t before = output_wall_milliseconds();
        ssize_t sent =
            sendto(fd, bytes, length, 0, (struct sockaddr*)&destination, sizeof(destination));
        size_t total = length + (cases[test].udp ? 28 : 20) + option_length;
        if (total > 65535 || (cases[test].policy >= 2 && cases[test].policy <= 4 &&
                              total > (size_t)cases[test].mtu)) {
            require(sent == -1 && errno == EMSGSIZE, "DF rejects oversized output");
            output_control(control_fd, peer, lane, test, 1);
        } else
            require(sent == (ssize_t)length, "complete output datagram accepted");
        // The queued datagram must retain every byte after the syscall returns.
        memset(bytes, 0xa5, length);
        require(setsockopt(fd, IPPROTO_IP, IP_OPTIONS, NULL, 0) == 0,
                "description options clear independently of accepted output");
        output_acknowledgement(control_fd, lane, test, 1);
        printf("IPV4_FRAGMENT_OUTPUT_CASE index=%u test=%u option_bytes=%zu utc_before_ms=%llu "
               "utc_after_ms=%llu\n",
               lane + 1, test, option_length, (unsigned long long)before,
               (unsigned long long)output_wall_milliseconds());
    }
    struct ifreq restore = {0};
    snprintf(restore.ifr_name, sizeof(restore.ifr_name), "%s", name);
    restore.ifr_mtu = 1500;
    require(ioctl(control_fd, SIOCSIFMTU, &restore) == 0, "restore output MTU");
    output_control(control_fd, peer, lane, sizeof(cases) / sizeof(cases[0]), 0);
    free(bytes);
    require(close(control_fd) == 0 && close(raw) == 0 && close(udp) == 0, "output socket close");
    printf("IPV4_FRAGMENT_OUTPUT_PASS index=%u cases=%zu option_cases=24\n", lane + 1,
           sizeof(cases) / sizeof(cases[0]));
}

static void raw_header_checks(unsigned lane, const char* name, const struct sockaddr_in* peer) {
    static const size_t lengths[] = {28, 28, 28, 28,   28,   28, 68, 36, 36, 36, 28, 28,    28,
                                     28, 28, 28, 1500, 1501, 19, 28, 68, 69, 28, 28, 65535, 65536};
    int control_fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMP);
    unsigned filter = ~1u;
    require(control_fd >= 0 &&
                setsockopt(control_fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0 &&
                setsockopt(control_fd, 255, 1, &filter, sizeof(filter)) == 0,
            "raw header control socket");
    unsigned char* bytes = malloc(65536);
    require(bytes != NULL, "raw header packet storage");
    for (unsigned test = 0; test < sizeof(lengths) / sizeof(*lengths); test++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
        request.ifr_mtu = test == 20 || test == 21 ? 68 : 1500;
        require(ioctl(control_fd, SIOCSIFMTU, &request) == 0, "raw header device MTU");
        int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, test == 22 ? 75 : IPPROTO_RAW);
        require(fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1) == 0,
                "raw header output socket");
        int enabled = -1;
        socklen_t option_length = sizeof(enabled);
        require(getsockopt(fd, IPPROTO_IP, IP_HDRINCL, &enabled, &option_length) == 0 &&
                    option_length == 4 && enabled == (test != 22),
                "raw header mode default");
        enabled = 1;
        require(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &enabled, 4) == 0, "raw header mode enable");
        int ttl = 99, tos = 4;
        require(setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, 4) == 0 &&
                    setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, 4) == 0,
                "raw header description defaults differ from literal fields");
        const size_t length = lengths[test];
        memset(bytes, 0, 65536);
        size_t header = test == 6 || test == 19 ? 60 : test >= 7 && test <= 9 ? 28 : 20;
        bytes[0] = (unsigned char)((test == 5 ? 0x60 : 0x40) | header / 4);
        bytes[1] = 0x5a;
        bytes[2] = bytes[3] = 0x11;
        bytes[4] = test == 1 || test == 2 ? 0 : 0x13;
        bytes[5] = test == 1 || test == 2 ? 0 : 0x57;
        bytes[6] = test == 2 ? 0x40 : 0;
        bytes[8] = 35;
        bytes[9] = 75;
        bytes[10] = bytes[11] = 0xaa;
        if (test == 3) {
            bytes[12] = 192;
            bytes[14] = 2;
            bytes[15] = 1;
        }
        memcpy(bytes + 16, &peer->sin_addr.s_addr, 4);
        if (test == 4)
            bytes[19] = 77;
        for (size_t at = header; at < length; at++)
            bytes[at] = (unsigned char)(at * 37 + lane * 31 + test * 11);
        if (test == 6)
            memset(bytes + 20, 1, 40);
        if (test >= 7 && test <= 9) {
            const unsigned char options[][8] = {{7, 7, 4, 99, 98, 97, 96, 0},
                                                {131, 7, 4, 10, 23, 9, 77, 0},
                                                {134, 8, 0, 0, 0, 0, 0, 0}};
            memcpy(bytes + 20, options[test - 7], 8);
        }
        if (test == 10 || test == 11) {
            const unsigned char options[4] = {1, 1, 1, 1};
            require(setsockopt(fd, IPPROTO_IP, IP_OPTIONS, options, test == 10 ? 0 : 4) == 0,
                    "raw header conflicting description options");
        }
        send_control(control_fd, peer, lane, "RH", test, 0);
        acknowledgement(control_fd, lane, "RH", test, 0, 5000);
        ssize_t sent;
        if (test == 23) {
            pid_t child = fork();
            require(child >= 0, "raw header inherited fork");
            if (!child) {
                require(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0,
                        "raw header ordinary credentials");
                enabled = 0;
                require(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &enabled, 4) == 0,
                        "raw header inherited clear");
                enabled = 1;
                require(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &enabled, 4) == 0 &&
                            sendto(fd, bytes, length, 0, (const struct sockaddr*)peer,
                                   sizeof(*peer)) == (ssize_t)length,
                        "raw header inherited ordinary output");
                memset(bytes, 0xa5, length);
                _exit(0);
            }
            int status;
            require(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                        WEXITSTATUS(status) == 0,
                    "raw header ordinary completion");
            sent = (ssize_t)length;
        } else if (test == 12 || test == 13) {
            unsigned char ancillary[CMSG_SPACE(4)] = {0};
            struct iovec vector = {.iov_base = bytes, .iov_len = length};
            struct msghdr message = {.msg_name = (void*)peer,
                                     .msg_namelen = sizeof(*peer),
                                     .msg_iov = &vector,
                                     .msg_iovlen = 1,
                                     .msg_control = ancillary,
                                     .msg_controllen = test == 12 ? CMSG_SPACE(0) : CMSG_SPACE(4)};
            struct cmsghdr* control = CMSG_FIRSTHDR(&message);
            control->cmsg_level = IPPROTO_IP;
            control->cmsg_type = IP_RETOPTS;
            control->cmsg_len = test == 12 ? CMSG_LEN(0) : CMSG_LEN(4);
            if (test == 13)
                memset(CMSG_DATA(control), 1, 4);
            sent = sendmsg(fd, &message, 0);
        } else
            sent = sendto(fd, bytes, length,
                          test == 14   ? 0x10
                          : test == 15 ? MSG_MORE
                                       : 0,
                          (const struct sockaddr*)peer, sizeof(*peer));
        int expected = test >= 10 && test <= 13                 ? EINVAL
                       : test == 17 || test == 21 || test >= 24 ? EMSGSIZE
                       : test == 18 || test == 19               ? EINVAL
                                                                : 0;
        require(expected ? sent == -1 && errno == expected : sent == (ssize_t)length,
                "raw header complete send result");
        memset(bytes, 0xa5, length);
        enabled = 0;
        require(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &enabled, 4) == 0,
                "raw header accepted mode ownership");
        if (expected || test == 14)
            send_control(control_fd, peer, lane, "RH", test, 1);
        acknowledgement(control_fd, lane, "RH", test, 1, 5000);
        require(close(fd) == 0, "raw header output close");
        printf("IPV4_RAW_HEADER_OUTPUT_CASE index=%u test=%u result=%lld error=%d ordinary=%u\n",
               lane + 1, test, (long long)sent, expected, test == 23);
    }
    struct ifreq restore = {0};
    snprintf(restore.ifr_name, sizeof(restore.ifr_name), "%s", name);
    restore.ifr_mtu = 1500;
    require(ioctl(control_fd, SIOCSIFMTU, &restore) == 0, "raw header restore device MTU");
    send_control(control_fd, peer, lane, "RH", 26, 0);
    acknowledgement(control_fd, lane, "RH", 26, 0, 5000);
    free(bytes);
    require(close(control_fd) == 0, "raw header control close");
    printf("IPV4_RAW_HEADER_OUTPUT_PASS index=%u cases=26 inherited_cases=1\n", lane + 1);
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
    for (unsigned test = 0; test < 12; test++) {
        control(fd, &peer, lane, test, 0);
        if (test >= 2 && test <= 4) {
            receive_packet(fd, lane, test, 1);
            control(fd, &peer, lane, test, 1);
        }
        receive_packet(fd, lane, test, 0);
        if (test == 4)
            receive_packet(fd, lane, test, 1);
    }
    control(fd, &peer, lane, 12, 0);
    require(close(fd) == 0, "raw socket close");
    printf("IPV4_FRAGMENT_PASS index=%u cases=12 option_cases=6\n", lane + 1);
    output_checks(lane, name, &peer);
    raw_header_checks(lane, name, &peer);
    ipv4_raw_header_queue_checks(lane, -1);
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

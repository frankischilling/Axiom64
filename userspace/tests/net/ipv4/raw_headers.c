// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned cases;

static void check(int condition, const char* name) {
    if (!condition) {
        printf("IPV4_RAW_HEADERS_FAIL case=%s errno=%d uid=%u\n", name, errno, geteuid());
        exit(1);
    }
    cases++;
}

static int query(int fd) {
    int value = -1;
    socklen_t length = sizeof(value);
    check(getsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, &length) == 0 && length == 4, "query");
    return value;
}

static void scalar(int fd, int raw, int initial) {
    check(query(fd) == initial, "default");
    const unsigned char values[][8] = {{0},
                                       {1},
                                       {255},
                                       {1, 0},
                                       {0, 0, 1},
                                       {1, 0, 0, 0},
                                       {255, 255, 255, 255},
                                       {1, 1, 1, 1, 1, 1, 1, 1}};
    const socklen_t lengths[] = {0, 1, 1, 2, 3, 4, 4, 8};
    for (unsigned n = 0; n < sizeof(lengths) / sizeof(*lengths); n++) {
        int result = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, values[n], lengths[n]);
        check(raw ? result == 0 : result == -1 && errno == ENOPROTOOPT, "setter");
        check(query(fd) == (raw && lengths[n] && values[n][0] != 0), "normalized");
    }
    int before = query(fd);
    for (unsigned n = 0; n < 5; n++) {
        const socklen_t sizes[] = {0, 1, 4, 41, (socklen_t)-1};
        errno = 0;
        int result = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, (void*)(uintptr_t)1, sizes[n]);
        int expected = n == 4 ? EINVAL : n == 0 ? (raw ? 0 : ENOPROTOOPT) : EFAULT;
        check(expected ? result == -1 && errno == expected : result == 0, "setter-pointer-order");
        if (raw && n == 0)
            before = 0;
        check(query(fd) == before, "failed-setter-atomic");
    }
    for (socklen_t size = 0; size <= 8; size++) {
        unsigned char bytes[8];
        memset(bytes, 0xa5, sizeof(bytes));
        socklen_t length = size;
        unsigned actual = size >= 4 ? 4 : size ? 1 : 0;
        check(getsockopt(fd, IPPROTO_IP, IP_HDRINCL, bytes, &length) == 0 && length == actual,
              "query-capacity");
        check(bytes[actual] == 0xa5 && (!actual || bytes[0] == before), "query-boundary");
    }
}

static uint16_t checksum(const unsigned char* bytes, unsigned length) {
    uint32_t sum = 0;
    for (unsigned n = 0; n < length; n += 2)
        sum += (unsigned)bytes[n] * 256 + bytes[n + 1];
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~sum;
}

static void packet(unsigned char* bytes, unsigned length, unsigned header, unsigned protocol,
                   unsigned identity, unsigned fragment) {
    memset(bytes, 0, length);
    bytes[0] = (unsigned char)(0x40 | header / 4);
    bytes[1] = 0x5a;
    bytes[2] = 0x11;
    bytes[3] = 0x11;
    bytes[4] = identity >> 8;
    bytes[5] = identity;
    bytes[6] = fragment >> 8;
    bytes[7] = fragment;
    bytes[8] = 35;
    bytes[9] = protocol;
    bytes[10] = bytes[11] = 0xaa;
    bytes[16] = 127;
    bytes[19] = 1;
    memset(bytes + 20, 1, header - 20);
    for (unsigned n = header; n < length; n++)
        bytes[n] = (unsigned char)(n * 37 + 11);
}

static void loopback(int sender, int receiver, unsigned protocol) {
    const struct sockaddr_in destination = {.sin_family = AF_INET,
                                            .sin_addr.s_addr = htonl(0x7f000001)};
    for (unsigned n = 0; n < 4; n++) {
        unsigned length = n == 3 ? 68 : 28, header = n == 3 ? 60 : 20;
        unsigned identity = n == 0 || n == 3 ? 0x1357 : 0;
        unsigned fragment = n == 2 ? 0x4000 : 0;
        unsigned char bytes[68], received[100];
        packet(bytes, length, header, protocol, identity, fragment);
        unsigned char original[68];
        memcpy(original, bytes, length);
        check(sendto(sender, bytes, length, n == 3 ? MSG_MORE : 0,
                     (const struct sockaddr*)&destination, sizeof(destination)) == (ssize_t)length,
              "literal-send");
        check(memcmp(bytes, original, length) == 0, "caller-buffer-preserved");
        memset(bytes, 0xcc, length);
        ssize_t count = recv(receiver, received, sizeof(received), 0);
        check(count == (ssize_t)length && (received[0] & 15) * 4u == header &&
                  received[1] == 0x5a && received[8] == 35 && received[9] == protocol &&
                  checksum(received, header) == 0 && received[2] == 0 && received[3] == length &&
                  received[12] == 127 && received[15] == 1 &&
                  memcmp(received + 16, original + 16, length - 16) == 0,
              "literal-receive");
        unsigned actual = (unsigned)received[4] * 256 + received[5];
        check(identity ? actual == identity : fragment ? actual == 0 : 1, "identity-policy");
        printf("IPV4_RAW_HEADERS_BYTES uid=%u protocol=%u case=%u length=%u bytes=", geteuid(),
               protocol, n, length);
        for (unsigned at = 0; at < length; at++)
            printf("%02x", received[at]);
        putchar('\n');
    }
    for (unsigned n = 0; n < 3; n++) {
        const size_t lengths[] = {19, 20, 65536};
        const int errors[] = {EINVAL, EFAULT, EMSGSIZE};
        check(sendto(sender, (void*)(uintptr_t)1, lengths[n], 0,
                     (const struct sockaddr*)&destination, sizeof(destination)) == -1 &&
                  errno == errors[n],
              "send-fault-order");
    }
    check(sendto(sender, (void*)(uintptr_t)1, 20, 0x10, (const struct sockaddr*)&destination,
                 sizeof(destination)) == 20,
          "probe-no-copy");
    unsigned char unused[100];
    check(recv(receiver, unused, sizeof(unused), MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "probe-no-output");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(30);
    check(geteuid() == 0, "root-fixture");
    const char* runtime = getenv("IPV4_OPTIONS_RUNTIME_FD");
    if (runtime) {
        char byte;
        int fd = atoi(runtime);
        check(read(fd, &byte, 1) == 1 && byte == 1 && close(fd) == 0, "runtime-barrier");
    }
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    check(raw >= 0, "raw255-create");
    int udp = socket(AF_INET, SOCK_DGRAM, 0), tcp = socket(AF_INET, SOCK_STREAM, 0);
    int generic = socket(AF_INET, SOCK_RAW, 75), wide = socket(AF_INET, SOCK_RAW, 262);
    check(udp >= 0 && tcp >= 0 && generic >= 0 && wide >= 0, "other-create");
    scalar(udp, 0, 0);
    scalar(tcp, 0, 0);
    scalar(generic, 1, 0);
    scalar(wide, 1, 0);
    scalar(raw, 1, 1);
    int enabled = 1;
    check(setsockopt(raw, IPPROTO_IP, IP_HDRINCL, &enabled, 4) == 0, "enable");
    loopback(raw, generic, 75);
    check(setsockopt(generic, IPPROTO_IP, IP_HDRINCL, &enabled, 4) == 0, "generic-enable");
    loopback(generic, raw, 255);
    unsigned char control[CMSG_SPACE(0)] = {0};
    struct iovec vector = {.iov_base = (void*)(uintptr_t)1, .iov_len = 20};
    struct sockaddr_in control_target = {.sin_family = AF_INET,
                                         .sin_addr.s_addr = htonl(0x7f000001)};
    struct msghdr message = {.msg_name = &control_target,
                             .msg_namelen = sizeof(control_target),
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control,
                             .msg_controllen = sizeof(control)};
    struct cmsghdr* ancillary = CMSG_FIRSTHDR(&message);
    ancillary->cmsg_level = IPPROTO_IP;
    ancillary->cmsg_type = IP_RETOPTS;
    ancillary->cmsg_len = CMSG_LEN(0);
    check(sendmsg(generic, &message, 0) == -1 && errno == EINVAL,
          "empty-message-options-conflict-before-copy");
    check(setsockopt(raw, IPPROTO_IP, IP_OPTIONS, NULL, 0) == 0, "empty-options");
    const struct sockaddr_in destination = {.sin_family = AF_INET,
                                            .sin_addr.s_addr = htonl(0x7f000001)};
    check(sendto(raw, (void*)(uintptr_t)1, 20, 0, (const struct sockaddr*)&destination,
                 sizeof(destination)) == -1 &&
              errno == EINVAL,
          "empty-options-conflict-before-copy");
    pid_t child = fork();
    check(child >= 0, "fork");
    if (!child) {
        check(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0,
              "ordinary-credentials");
        scalar(generic, 1, 1);
        check(setsockopt(generic, IPPROTO_IP, IP_HDRINCL, &enabled, 4) == 0, "ordinary-enable");
        loopback(generic, raw, 255);
        enabled = 0;
        check(setsockopt(generic, IPPROTO_IP, IP_HDRINCL, &enabled, 4) == 0, "ordinary-clear");
        check(socket(AF_INET, SOCK_RAW, 255) == -1 && errno == EPERM, "creation-capability");
        puts("IPV4_RAW_HEADERS_ORDINARY_PASS");
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "ordinary-completion");
    check(query(generic) == 0, "shared-description");
    check(close(raw) == 0 && close(generic) == 0 && close(wide) == 0 && close(udp) == 0 &&
              close(tcp) == 0,
          "close");
    printf("IPV4_RAW_HEADERS_PASS cases=%u\n", cases);
    return 0;
}

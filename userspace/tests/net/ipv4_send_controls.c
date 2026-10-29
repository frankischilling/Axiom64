// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static unsigned cases, loopback;

static void check(int accepted, const char* operation) {
    if (!accepted) {
        printf("IPV4_SEND_CONTROLS_FAIL case=%u operation=%s error=%d\n", cases, operation, errno);
        exit(1);
    }
}

static void hex(const void* pointer, size_t length) {
    const unsigned char* bytes = pointer;
    for (size_t at = 0; at < length; at++)
        printf("%02x", bytes[at]);
    if (!length)
        putchar('-');
}

static void append(unsigned char* bytes, size_t* length, int level, int type, const void* value,
                   size_t size) {
    struct cmsghdr header = {.cmsg_len = CMSG_LEN(size), .cmsg_level = level, .cmsg_type = type};
    memcpy(bytes + *length, &header, sizeof(header));
    if (size)
        memcpy(bytes + *length + sizeof(header), value, size);
    *length += CMSG_SPACE(size);
}

static int option(int fd, int name) {
    int value = -999;
    socklen_t length = sizeof(value);
    check(!getsockopt(fd, IPPROTO_IP, name, &value, &length) && length == sizeof(value),
          "shared-option");
    return value;
}

static struct sockaddr_in local(int fd) {
    struct sockaddr_in address = {0};
    socklen_t length = sizeof(address);
    check(!getsockname(fd, (struct sockaddr*)&address, &length) && length == sizeof(address),
          "local-description");
    return address;
}

static uint16_t checksum(const unsigned char* bytes, size_t length) {
    uint32_t value = 0;
    for (size_t at = 0; at < length; at += 2)
        value += (uint16_t)bytes[at] << 8 | (at + 1 < length ? bytes[at + 1] : 0);
    while (value >> 16)
        value = (value & 65535) + (value >> 16);
    return (uint16_t)~value;
}

static size_t payload(unsigned char* bytes, unsigned kind, unsigned variant, unsigned baseline,
                      unsigned char token[24]) {
    for (unsigned at = 0; at < 24; at++)
        token[at] = (unsigned char)(at * 19 + 7);
    memcpy(token, "SCTL", 4);
    token[4] = kind;
    token[5] = variant;
    token[6] = baseline;
    if (!kind) {
        memcpy(bytes, token, 24);
        return 24;
    }
    memset(bytes, 0, 8);
    if (kind == 1) {
        uint16_t fields[] = {htons(55101), htons(55100), htons(32), 0};
        memcpy(bytes, fields, 8);
    } else {
        bytes[0] = 253;
        bytes[4] = 0x6d;
        bytes[5] = 0x53;
    }
    memcpy(bytes + 8, token, 24);
    if (kind == 2) {
        uint16_t value = htons(checksum(bytes, 32));
        memcpy(bytes + 2, &value, 2);
    }
    return 32;
}

static size_t packet(int fd, unsigned protocol, const unsigned char token[24],
                     unsigned char bytes[256]) {
    struct pollfd wait = {.fd = fd, .events = POLLIN};
    int ready = poll(&wait, 1, 500);
    check(ready >= 0, "packet-poll");
    if (!ready)
        return 0;
    for (;;) {
        ssize_t length = recv(fd, bytes, 256, MSG_DONTWAIT);
        if (length < 0) {
            check(errno == EAGAIN, "packet-read");
            return 0;
        }
        if (length < 20 || (bytes[0] >> 4) != 4 || bytes[9] != protocol)
            continue;
        size_t header = (bytes[0] & 15) * 4;
        if (header >= 20 && (size_t)length == header + 32 && !memcmp(bytes + header + 8, token, 24))
            return length;
    }
}

static void observation(int sender, int observer, int receiver, struct msghdr* message,
                        unsigned kind, unsigned named, unsigned variant, unsigned baseline,
                        const unsigned char token[24], struct sockaddr_in before,
                        const unsigned char controls[192], const unsigned char original[192]) {
    struct msghdr original_message = *message;
    errno = 0;
    long result = syscall(SYS_sendmsg, sender, message, MSG_DONTWAIT | MSG_NOSIGNAL);
    int error = result < 0 ? errno : 0;
    int unchanged = !memcmp(controls, original, 192) &&
                    !memcmp(message, &original_message, sizeof(original_message));
    struct sockaddr_in after = local(sender);
    unsigned char bytes[256], delivered[64];
    size_t length = result < 0 ? 0 : packet(observer, kind == 2 ? 1 : 17, token, bytes);
    ssize_t count = receiver < 0 ? -1 : recv(receiver, delivered, sizeof(delivered), MSG_DONTWAIT);
    int delivery_error = count < 0 ? (receiver < 0 ? 0 : errno) : 0;
    printf("IPV4_SEND_CASE kind=%u named=%u variant=%u baseline=%u result=%ld error=%d "
           "before=%08x:%u after=%08x:%u ttl=%d tos=%d unchanged=%d packet=",
           kind, named, variant, baseline, result, error, ntohl(before.sin_addr.s_addr),
           ntohs(before.sin_port), ntohl(after.sin_addr.s_addr), ntohs(after.sin_port),
           option(sender, IP_TTL), option(sender, IP_TOS), unchanged);
    hex(bytes, length);
    printf(" delivery=%zd delivery_error=%d body=", count, delivery_error);
    hex(delivered, count > 0 ? (size_t)count : 0);
    putchar('\n');
    if (baseline)
        check(unchanged && result == (kind ? 32 : 24) && length &&
                  (kind == 2 || (count == 24 && !memcmp(delivered, token, 24))),
              "baseline-output");
}

static void one(unsigned kind, unsigned named, unsigned variant) {
    unsigned protocol = kind == 2 ? 1 : 17;
    int sender = socket(AF_INET, (kind ? SOCK_RAW : SOCK_DGRAM) | SOCK_NONBLOCK, protocol);
    int observer = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, protocol);
    int receiver = kind == 2 ? -1 : socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    check(sender >= 0 && observer >= 0 && (kind == 2 || receiver >= 0), "descriptions");
    int alias = dup(sender), ttl = 63, tos = 34;
    check(alias >= 0 && !setsockopt(alias, IPPROTO_IP, IP_TTL, &ttl, 4) &&
              !setsockopt(alias, IPPROTO_IP, IP_TOS, &tos, 4),
          "description-defaults");
    struct sockaddr_in destination = {
        .sin_family = AF_INET, .sin_port = htons(55100), .sin_addr.s_addr = htonl(0x7f000001)};
    struct sockaddr_in wildcard = {.sin_family = AF_INET, .sin_port = htons(55100)};
    check(receiver < 0 || !bind(receiver, (struct sockaddr*)&wildcard, sizeof(wildcard)),
          "receiver-bind");
    if (!named)
        check(!connect(sender, (struct sockaddr*)&destination, sizeof(destination)), "connected");
    struct sockaddr_in before = local(sender);
    unsigned char body[32], token[24], controls[192] = {0}, original[192], names[129] = {0};
    size_t body_length = payload(body, kind, variant, 0, token), length = 0;
    memcpy(names, &destination, sizeof(destination));
    int value = 37;
    struct in_pktinfo info = {.ipi_ifindex = loopback,
                              .ipi_spec_dst.s_addr = htonl(0x7f000002),
                              .ipi_addr.s_addr = htonl(0xdeadbeef)};
    if (variant == 1 || variant == 4 || variant == 5 || (variant >= 6 && variant <= 8) ||
        variant == 12 || (variant >= 27 && variant <= 32) || variant == 56 || variant == 57 ||
        variant == 63) {
        if (variant >= 6 && variant <= 8)
            value = variant == 6 ? 0 : variant == 7 ? -1 : 256;
        if (variant == 56)
            value = 0;
        append(controls, &length, IPPROTO_IP, IP_TTL, &value, variant == 12 ? 1 : 4);
    }
    if (variant == 2 || variant == 4 || (variant >= 9 && variant <= 11) || variant == 63) {
        value = variant == 9 ? -1 : variant == 10 ? 256 : variant == 11 ? 254 : 184;
        append(controls, &length, IPPROTO_IP, IP_TOS, &value, variant == 11 ? 1 : 4);
    }
    if (variant == 3 || variant == 4 || (variant >= 13 && variant <= 18) ||
        (variant >= 52 && variant <= 55) || variant == 59 || (variant >= 61 && variant <= 63)) {
        if (variant == 15 || variant == 17 || (variant >= 52 && variant <= 54))
            info.ipi_spec_dst.s_addr = htonl(0xcb007108);
        if (variant == 16 || variant == 17 || variant == 55)
            info.ipi_ifindex = 999999;
        if (variant == 61)
            info.ipi_spec_dst.s_addr = 0;
        if (variant == 62)
            info.ipi_ifindex = 0;
        unsigned char extended[13] = {0};
        memcpy(extended, &info, sizeof(info));
        append(controls, &length, IPPROTO_IP, IP_PKTINFO, extended,
               variant == 13   ? 11
               : variant == 14 ? 13
                               : sizeof(info));
    }
    if (variant == 5) {
        value = 41;
        append(controls, &length, IPPROTO_IP, IP_TTL, &value, 4);
    }
    if (variant == 18) {
        memset(&info, 0, sizeof(info));
        append(controls, &length, IPPROTO_IP, IP_PKTINFO, &info, sizeof(info));
    }
    if (variant >= 19 && variant <= 25) {
        unsigned char data[12] = {0};
        if (variant == 21)
            memcpy(data, &alias, sizeof(alias));
        append(controls, &length,
               variant == 19   ? IPPROTO_IP
               : variant == 20 ? 777
               : variant <= 23 ? SOL_SOCKET
                               : IPPROTO_UDP,
               variant == 21   ? SCM_RIGHTS
               : variant == 22 ? SCM_CREDENTIALS
               : variant == 25 ? 103
                               : 999,
               data,
               variant == 22   ? 12
               : variant == 25 ? 2
                               : 4);
    }
    if (variant == 27)
        length = 15;
    if (variant == 26) {
        append(controls, &length, IPPROTO_IP, IP_TTL, NULL, 0);
    }
    if (variant == 28)
        ((struct cmsghdr*)controls)->cmsg_len = 15;
    if (variant == 29)
        ((struct cmsghdr*)controls)->cmsg_len = 17;
    if (variant == 30)
        ((struct cmsghdr*)controls)->cmsg_len = 200;
    if (variant == 31)
        length++;
    if (variant == 32)
        length += sizeof(struct cmsghdr);
    struct iovec vector = {.iov_base = body, .iov_len = body_length};
    struct msghdr message = {.msg_name = named ? names : NULL,
                             .msg_namelen = named ? 16 : 0,
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = controls,
                             .msg_controllen = length};
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED, "input-pages");
    if (variant >= 33 && variant <= 36) {
        message.msg_control = (void*)1;
        message.msg_controllen = variant == 33   ? 0
                                 : variant == 34 ? 1
                                 : variant == 35 ? 16
                                                 : 131072;
    }
    if (variant == 37)
        message.msg_name = NULL;
    if (variant == 38) {
        message.msg_name = names;
        message.msg_namelen = 0;
    }
    if (variant == 39) {
        ((struct sockaddr_in*)names)->sin_family = AF_UNIX;
        message.msg_name = names;
        message.msg_namelen = 16;
    }
    if (variant == 40 || variant == 48) {
        message.msg_name = names;
        message.msg_namelen = 1;
    }
    if (variant == 41 || variant == 46) {
        message.msg_name = (void*)1;
        message.msg_namelen = 16;
    }
    if (variant == 42 || variant == 47) {
        message.msg_name = names;
        message.msg_namelen = (socklen_t)-1;
    }
    if (variant == 43) {
        message.msg_name = names;
        message.msg_namelen = sizeof(names);
    }
    if (variant == 44)
        message.msg_iov = (void*)1;
    if (variant == 45 || (variant >= 46 && variant <= 48))
        message.msg_iovlen = 1025;
    if (variant == 49 || variant == 52 || variant == 55 || variant == 56)
        vector.iov_base = (void*)1;
    if (variant == 50 || variant == 51 || variant == 53 || variant == 54) {
        size_t prefix = variant == 50 || variant == 53 ? 1 : 2;
        memcpy(pages + 4096 - prefix, body, prefix);
        vector.iov_base = pages + 4096 - prefix;
    }
    if (variant == 57) {
        memcpy(pages + 4096 - 16, controls, 16);
        message.msg_control = pages + 4096 - 16;
    }
    if (variant == 58) {
        memcpy(pages + 4096 - 16, names, 16);
        message.msg_name = pages + 4096 - 16;
        message.msg_namelen = 17;
    }
    if (variant == 59) {
        ((struct sockaddr_in*)names)->sin_addr.s_addr = 0;
        message.msg_name = names;
        message.msg_namelen = 16;
    }
    if (variant == 60) {
        ((struct sockaddr_in*)names)->sin_family = AF_UNSPEC;
        message.msg_name = names;
        message.msg_namelen = 16;
    }
    check(!mprotect(pages + 4096, 4096, PROT_NONE), "input-guard");
    memcpy(original, controls, sizeof(original));
    printf("IPV4_SEND_INPUT kind=%u named=%u variant=%u control=", kind, named, variant);
    hex(controls, length);
    printf(" name_length=%u vector_count=%zu body_length=%zu\n", message.msg_namelen,
           (size_t)message.msg_iovlen, body_length);
    observation(sender, observer, receiver, &message, kind, named, variant, 0, token, before,
                controls, original);
    check(!memcmp(original, controls, sizeof(original)) && option(alias, IP_TTL) == 63 &&
              option(alias, IP_TOS) == 34,
          "immutable-input-and-defaults");
    body_length = payload(body, kind, variant, 1, token);
    vector = (struct iovec){.iov_base = body, .iov_len = body_length};
    message = (struct msghdr){.msg_name = &destination,
                              .msg_namelen = sizeof(destination),
                              .msg_iov = &vector,
                              .msg_iovlen = 1};
    observation(alias, observer, receiver, &message, kind, named, variant, 1, token, local(sender),
                controls, original);
    check(!munmap(pages, 8192), "input-release");
    close(alias);
    close(sender);
    close(observer);
    if (receiver >= 0)
        close(receiver);
    cases++;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    loopback = if_nametoindex("lo");
    check(loopback != 0, "loopback-index");
    printf("IPV4_SEND_CONTROLS_BEGIN loopback=%u\n", loopback);
    for (unsigned kind = 0; kind < 3; kind++)
        for (unsigned named = 0; named < 2; named++)
            for (unsigned variant = 0; variant < 64; variant++)
                one(kind, named, variant);
    printf("IPV4_SEND_CONTROLS_DONE cases=%u observations=%u\n", cases, cases * 2);
    return 0;
}

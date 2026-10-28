// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static unsigned checks, observations;
static const int options[] = {IP_PKTINFO, IP_RECVTTL, IP_RECVTOS};

static void need(int condition, const char* label) {
    checks++;
    if (!condition) {
        fprintf(stderr, "IPV4_RECEIVE_CONTROLS_FAIL %s errno=%d\n", label, errno);
        exit(1);
    }
}

static void hex(const unsigned char* bytes, size_t length) {
    for (size_t n = 0; n < length; n++)
        printf("%02x", bytes[n]);
}

static struct sockaddr_in address(uint32_t value, uint16_t port) {
    struct sockaddr_in result = {
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(value)};
    return result;
}

static struct sockaddr_in bound(int fd) {
    struct sockaddr_in result;
    socklen_t length = sizeof(result);
    need(!getsockname(fd, (struct sockaddr*)&result, &length) && length == sizeof(result),
         "actual local address");
    return result;
}

static void enable(int fd, unsigned mask) {
    for (unsigned n = 0; n < 3; n++) {
        int value = !!(mask & (1u << n));
        need(!setsockopt(fd, IPPROTO_IP, options[n], &value, sizeof(value)), "receive option");
    }
}

static int query(int fd, int option) {
    int value = -1;
    socklen_t length = sizeof(value);
    need(!getsockopt(fd, IPPROTO_IP, option, &value, &length) && length == sizeof(value),
         "receive option query");
    return value;
}

static void option_cases(void) {
    const int kinds[] = {SOCK_DGRAM, SOCK_RAW, SOCK_STREAM};
    const unsigned char values[][4] = {
        {0}, {0x80}, {1, 0x99}, {0, 0xff, 0xff}, {0xff, 0xff, 0xff, 0xff}, {0}, {0, 0, 0, 1}};
    const socklen_t sizes[] = {0, 1, 2, 3, 4, 4, 4};
    const int expected[] = {0, 1, 1, 0, 1, 0, 1};
    for (unsigned kind = 0; kind < 3; kind++) {
        int fd = socket(AF_INET, kinds[kind] | SOCK_CLOEXEC, kind == 2 ? IPPROTO_TCP : IPPROTO_UDP);
        need(fd >= 0, "option socket");
        for (unsigned option = 0; option < 3; option++) {
            need(query(fd, options[option]) == 0, "fresh description options disabled");
            for (unsigned value = 0; value < 7; value++) {
                need(!setsockopt(fd, IPPROTO_IP, options[option], values[value], sizes[value]),
                     "zero byte short integer and negative option inputs");
                need(query(fd, options[option]) == expected[value], "boolean option normalization");
                for (socklen_t capacity = 0; capacity <= 6; capacity++) {
                    unsigned char bytes[12];
                    memset(bytes, 0xa5, sizeof(bytes));
                    socklen_t length = capacity;
                    need(!getsockopt(fd, IPPROTO_IP, options[option], bytes, &length),
                         "short option result");
                    socklen_t actual = capacity >= 4 ? 4 : capacity ? 1 : 0;
                    need(length == actual, "actual short option length");
                    for (unsigned n = 0; n < sizeof(bytes); n++)
                        need(bytes[n] == (n < actual ? n ? 0 : expected[value] : 0xa5),
                             "option value and untouched suffix");
                }
                printf("{\"kind\":\"option\",\"socket\":%u,\"option\":%d,\"length\":%u,"
                       "\"input\":\"",
                       kind, options[option], sizes[value]);
                hex(values[value], sizes[value]);
                printf("\",\"value\":%d}\n", query(fd, options[option]));
            }
            int previous = query(fd, options[option]);
            errno = 0;
            need(syscall(SYS_setsockopt, fd, IPPROTO_IP, options[option], 1, 4) == -1 &&
                     errno == EFAULT && query(fd, options[option]) == previous,
                 "failed option copy preserves state");
            errno = 0;
            need(syscall(SYS_setsockopt, fd, IPPROTO_IP, options[option], 1, -1) == -1 &&
                     errno == EINVAL && query(fd, options[option]) == previous,
                 "negative option length precedes input copy");
            need(!syscall(SYS_setsockopt, fd, IPPROTO_IP, options[option], 1, 0) &&
                     query(fd, options[option]) == 0,
                 "zero option length ignores invalid pointer and disables");
        }
        need(!close(fd), "option description close");
    }
}

static unsigned checksum(const unsigned char* bytes, size_t length) {
    unsigned sum = 0;
    for (size_t n = 0; n < length; n += 2)
        sum += ((unsigned)bytes[n] << 8) | (n + 1 < length ? bytes[n + 1] : 0);
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}

static void put16(unsigned char* bytes, unsigned value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}

struct Transport {
    int receiver, sender, guard;
    unsigned kind;
    struct sockaddr_in target, source;
};

static struct Transport transport(unsigned kind) {
    int protocol = kind == 1 ? IPPROTO_ICMP : IPPROTO_UDP;
    struct Transport value = {.kind = kind, .guard = -1};
    value.receiver = socket(AF_INET, (kind ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC, protocol);
    value.sender = socket(AF_INET, (kind ? SOCK_RAW : SOCK_DGRAM) | SOCK_CLOEXEC, protocol);
    need(value.receiver >= 0 && value.sender >= 0, "data descriptions");
    value.target = address(0x7f000002, 0);
    value.source = address(0x7f000001, 0);
    need(!bind(value.receiver, (struct sockaddr*)&value.target, sizeof(value.target)),
         "receive loopback address");
    need(!bind(value.sender, (struct sockaddr*)&value.source, sizeof(value.source)),
         "send loopback address");
    if (kind == 2) {
        value.guard = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        need(value.guard >= 0 &&
                 !bind(value.guard, (struct sockaddr*)&value.target, sizeof(value.target)),
             "raw UDP paired datagram description");
        value.target = bound(value.guard);
    } else if (!kind)
        value.target = bound(value.receiver);
    value.source = bound(value.sender);
    int ttl = 37, tos = 0x6e;
    need(!setsockopt(value.sender, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) &&
             !setsockopt(value.sender, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)),
         "actual transmitted TTL and TOS");
    return value;
}

static void send_packet(struct Transport* value, const unsigned char body[16]) {
    unsigned char packet[24] = {0};
    const void* data = body;
    size_t length = 16;
    if (value->kind) {
        memcpy(packet + 8, body, 16);
        if (value->kind == 1) {
            packet[0] = 8;
            packet[4] = 0x51;
            packet[5] = 0x42;
            put16(packet + 2, checksum(packet, sizeof(packet)));
        } else {
            put16(packet, 41001);
            memcpy(packet + 2, &value->target.sin_port, 2);
            put16(packet + 4, sizeof(packet));
            unsigned char pseudo[36] = {127, 0, 0, 1, 127, 0, 0, 2, 0, IPPROTO_UDP, 0, 24};
            memcpy(pseudo + 12, packet, sizeof(packet));
            unsigned sum = checksum(pseudo, sizeof(pseudo));
            put16(packet + 6, sum ? sum : 65535);
        }
        data = packet;
        length = sizeof(packet);
    }
    need(sendto(value->sender, data, length, 0, (struct sockaddr*)&value->target,
                sizeof(value->target)) == (ssize_t)length,
         "actual datagram send");
    if (value->guard >= 0) {
        unsigned char copy[32];
        struct pollfd ready = {.fd = value->guard, .events = POLLIN};
        need(poll(&ready, 1, 1000) == 1 && recv(value->guard, copy, sizeof(copy), 0) == 16 &&
                 !memcmp(copy, body, 16),
             "raw UDP also reached its datagram description");
    }
    struct pollfd ready = {.fd = value->receiver, .events = POLLIN};
    unsigned char first;
    need(poll(&ready, 1, 1000) == 1 &&
             recv(value->receiver, &first, 1, MSG_PEEK | MSG_DONTWAIT) == 1,
         "actual packet is queued before option selection");
}

static void receive_case(struct Transport* value, unsigned prepared, unsigned mask,
                         unsigned capacity) {
    unsigned char body[16] = {'A', 'X', 'I', 'P', 'M', 'E', 'T', 'A'};
    for (unsigned n = 8; n < sizeof(body); n++)
        body[n] = (observations * 17 + n * 29) & 255;
    enable(value->receiver, prepared ? 1 : 0);
    send_packet(value, body);
    enable(value->receiver, mask);
    unsigned char bytes[64];
    memset(bytes, 0xa5, sizeof(bytes));

    union {
        max_align_t alignment;
        unsigned char bytes[128];
    } controls;

    memset(&controls, 0xa5, sizeof(controls));
    size_t expected = value->kind ? 44 : 16;
    struct iovec vectors[2] = {{bytes, 7}, {bytes + 7, expected - 7}};
    struct sockaddr_in source;
    memset(&source, 0xa5, sizeof(source));
    struct msghdr message = {.msg_name = &source,
                             .msg_namelen = sizeof(source),
                             .msg_iov = vectors,
                             .msg_iovlen = 2,
                             .msg_control = controls.bytes,
                             .msg_controllen = capacity,
                             .msg_flags = 0x7fffffff};
    ssize_t result = recvmsg(value->receiver, &message, MSG_DONTWAIT);
    need(result == (ssize_t)expected && message.msg_namelen == sizeof(source) &&
             source.sin_family == AF_INET && source.sin_addr.s_addr == htonl(0x7f000001) &&
             source.sin_port == (value->kind ? 0 : value->source.sin_port),
         "real receive length and source metadata");
    need(!(message.msg_flags & ~MSG_CTRUNC) && message.msg_controllen <= capacity,
         "receive flags and bounded ancillary length");
    unsigned char* payload = bytes;
    if (value->kind) {
        need(bytes[0] == 0x45 && bytes[8] == 37 && bytes[1] == 0x6e &&
                 bytes[9] == (value->kind == 1 ? IPPROTO_ICMP : IPPROTO_UDP) &&
                 !checksum(bytes, 20) && !memcmp(bytes + 12, "\177\0\0\1\177\0\0\2", 8),
             "actual raw IPv4 header and checksum");
        payload += 28;
    }
    need(!memcmp(payload, body, sizeof(body)), "actual received payload bytes");
    for (size_t n = message.msg_controllen; n < sizeof(controls.bytes); n++)
        need(controls.bytes[n] == 0xa5, "unreported control bytes stay untouched");
    for (size_t n = expected; n < sizeof(bytes); n++)
        need(bytes[n] == 0xa5, "unwritten payload suffix");
    printf("{\"kind\":\"receive\",\"case\":%u,\"transport\":%u,\"prepared\":%u,"
           "\"mask\":%u,\"capacity\":%u,\"result\":%zd,\"flags\":%d,"
           "\"control_length\":%zu,\"control_hex\":\"",
           observations, value->kind, prepared, mask, capacity, result, message.msg_flags,
           (size_t)message.msg_controllen);
    hex(controls.bytes, message.msg_controllen);
    printf("\",\"payload\":\"");
    hex(payload, 16);
    puts("\"}");
    observations++;
}

static void description_cases(void) {
    for (unsigned kind = 0; kind < 3; kind++) {
        struct Transport value = transport(kind);
        int duplicate = dup(value.receiver);
        need(duplicate >= 0, "duplicate receive description");
        enable(value.receiver, 1);
        need(query(duplicate, IP_PKTINFO) == 1, "duplicate shares receive options");
        pid_t child = fork();
        need(child >= 0, "fork shared receive description");
        if (!child) {
            enable(duplicate, 7);
            _exit(0);
        }
        int status = -1;
        need(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
             "child changed shared receive options");
        need(query(value.receiver, IP_PKTINFO) == 1 && query(value.receiver, IP_RECVTTL) == 1 &&
                 query(value.receiver, IP_RECVTOS) == 1,
             "parent sees child receive options");
        need(!close(value.receiver), "close first receive reference");
        value.receiver = duplicate;
        receive_case(&value, 1, 7, 96);
        need(!close(value.receiver) && !close(value.sender), "close final receive reference");
        if (value.guard >= 0)
            need(!close(value.guard), "close paired lifetime datagram");
        printf("{\"kind\":\"description\",\"transport\":%u,\"duplicate\":true,\"fork\":true}\n",
               kind);
    }
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    int sender = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    need(listener >= 0 && sender >= 0, "accept receive-option descriptions");
    struct sockaddr_in target = address(0x7f000001, 0);
    enable(listener, 5);
    need(!bind(listener, (struct sockaddr*)&target, sizeof(target)) && !listen(listener, 1),
         "listen with receive-option snapshot");
    target = bound(listener);
    need(!connect(sender, (struct sockaddr*)&target, sizeof(target)),
         "actual option-inheritance handshake");
    // Client completion does not prove the server has processed its final ACK.
    struct pollfd ready = {.fd = listener, .events = POLLIN};
    need(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN),
         "server child is established before listener changes");
    enable(listener, 2);
    int accepted = accept(listener, NULL, NULL);
    need(accepted >= 0, "accept established description");
    need(query(accepted, IP_PKTINFO) == 1 && query(accepted, IP_RECVTTL) == 0 &&
             query(accepted, IP_RECVTOS) == 1,
         "accepted description owns handshake snapshot");
    enable(accepted, 7);
    need(query(listener, IP_PKTINFO) == 0 && query(listener, IP_RECVTTL) == 1 &&
             query(listener, IP_RECVTOS) == 0,
         "accepted receive options are independent of listener");
    need(!close(accepted) && !close(sender) && !close(listener),
         "close inherited option descriptions");
    puts("{\"kind\":\"accepted\",\"snapshot\":5,\"listener\":2,\"independent\":true}");
}

static unsigned fault_observations;

static void fault_cases(void) {
    const unsigned visible[] = {0,  1,  7,  8,  11, 12, 15, 16, 17, 19, 20, 21, 23,
                                24, 27, 28, 29, 31, 32, 33, 35, 36, 39, 40, 47, 48,
                                49, 51, 52, 53, 55, 56, 57, 71, 72, 73, 96};
    long page = sysconf(_SC_PAGESIZE);
    need(page >= 4096, "actual fault page size");
    unsigned char* mapping =
        mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    need(mapping != MAP_FAILED && !mprotect(mapping + page, (size_t)page, PROT_NONE),
         "actual inaccessible control page");
    for (unsigned kind = 0; kind < 3; kind++) {
        struct Transport value = transport(kind);
        enable(value.receiver, 7);
        for (unsigned flags = 0; flags < 4; flags++) {
            int input = (flags & 1 ? MSG_PEEK : 0) | (flags & 2 ? MSG_TRUNC : 0);
            for (unsigned mode = 0; mode < 2 + sizeof(visible) / sizeof(visible[0]); mode++) {
                unsigned readable = mode < 2 ? 0 : visible[mode - 2];
                unsigned char* control = mode == 0   ? NULL
                                         : mode == 1 ? (void*)1
                                                     : mapping + page - readable;
                memset(mapping, 0xa5, (size_t)page);
                unsigned char body[16] = {'A', 'X', 'F', 'A', 'U', 'L', 'T', '0'};
                for (unsigned n = 8; n < sizeof(body); n++)
                    body[n] = (fault_observations * 19 + n * 13) & 255;
                send_packet(&value, body);
                unsigned char bytes[64];
                memset(bytes, 0xa5, sizeof(bytes));
                size_t capacity = kind ? 36 : 8;
                struct iovec vector = {bytes, capacity};
                struct sockaddr_in source;
                memset(&source, 0xa5, sizeof(source));
                struct msghdr message = {.msg_name = &source,
                                         .msg_namelen = sizeof(source),
                                         .msg_iov = &vector,
                                         .msg_iovlen = 1,
                                         .msg_control = control,
                                         .msg_controllen = 96,
                                         .msg_flags = 0x7fffffff};
                errno = 0;
                ssize_t result = recvmsg(value.receiver, &message, input | MSG_DONTWAIT);
                int error = errno;
                unsigned char drain[64];
                errno = 0;
                ssize_t queued =
                    recv(value.receiver, drain, sizeof(drain), MSG_DONTWAIT | MSG_PEEK);
                int queue_error = errno;
                if (queued >= 0)
                    need(recv(value.receiver, drain, sizeof(drain), MSG_DONTWAIT) == queued,
                         "drain exact peeked fault packet");
                printf("{\"kind\":\"fault\",\"case\":%u,\"transport\":%u,\"input_flags\":%d,"
                       "\"location\":%u,\"visible\":%u,\"result\":%zd,\"errno\":%d,"
                       "\"name_length\":%u,\"flags\":%d,\"control_length\":%zu,"
                       "\"queued\":%zd,\"queue_errno\":%d,\"control_hex\":\"",
                       fault_observations, kind, input, mode < 2 ? mode : 2, readable, result,
                       error, message.msg_namelen, message.msg_flags,
                       (size_t)message.msg_controllen, queued, queue_error);
                if (readable)
                    hex(control, readable);
                printf("\",\"payload\":\"");
                hex(bytes + (kind ? 28 : 0), 8);
                puts("\"}");
                fault_observations++;
            }
        }
        need(!close(value.receiver) && !close(value.sender), "close fault descriptions");
        if (value.guard >= 0)
            need(!close(value.guard), "close paired fault datagram");
    }
    need(!munmap(mapping, (size_t)page * 2), "release fault mappings");
}

int main(void) {
    setvbuf(stdout, NULL, _IOFBF, 32768);
    _Static_assert(sizeof(struct cmsghdr) == 16, "Linux x86-64 control header");
    _Static_assert(sizeof(struct in_pktinfo) == 12, "Linux IPv4 packet information");
    struct utsname identity;
    need(!uname(&identity), "actual kernel identity");
    unsigned loopback = if_nametoindex("lo");
    need(loopback != 0, "actual loopback interface index");
    printf("{\"kind\":\"kernel\",\"sysname\":\"%s\",\"release\":\"%s\",\"loopback\":%u}\n",
           identity.sysname, identity.release, loopback);
    option_cases();
    const unsigned capacities[] = {0,  1,  15, 16, 17, 19, 20, 21, 27, 28, 29, 31, 32, 33, 47,
                                   48, 49, 51, 52, 55, 56, 57, 71, 72, 73, 79, 80, 81, 96};
    for (unsigned kind = 0; kind < 3; kind++) {
        struct Transport value = transport(kind);
        for (unsigned prepared = 0; prepared < 2; prepared++)
            for (unsigned mask = 0; mask < 8; mask++)
                for (unsigned n = 0; n < sizeof(capacities) / sizeof(capacities[0]); n++)
                    receive_case(&value, prepared, mask, capacities[n]);
        need(!close(value.sender) && !close(value.receiver), "data description close");
        if (value.guard >= 0)
            need(!close(value.guard), "paired datagram description close");
    }
    description_cases();
    fault_cases();
    printf("IPV4_RECEIVE_CONTROLS_PASS observations=%u faults=%u checks=%u\n", observations,
           fault_observations, checks);
    return 0;
}

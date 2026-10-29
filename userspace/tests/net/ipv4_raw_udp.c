// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/icmp.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static unsigned operations, packets, quiet_windows;
static const uint32_t local = 0x7f000001, source_a = 0x7f000002, source_b = 0x7f000003;
static const uint32_t group = 0xef7f2a71;
static const unsigned source_port = 41000, data_port = 39901;

static void need(int okay, const char* label) {
    if (!okay) {
        fprintf(stderr, "RAW_UDP_FAIL operation=%s errno=%d\n", label, errno);
        exit(1);
    }
}

static void outcome(const char* label, long code, int error, long expected, int wanted_error) {
    printf("{\"kind\":\"operation\",\"label\":\"%s\",\"returncode\":%ld,\"errno\":%d}\n", label,
           code, error);
    need(code == expected && error == wanted_error, label);
    operations++;
}

#define EXPECT(label, expression, wanted, error)                                                   \
    do {                                                                                           \
        errno = 0;                                                                                 \
        long observed = (expression);                                                              \
        int saved = observed < 0 ? errno : 0;                                                      \
        outcome(label, observed, saved, wanted, error);                                            \
    } while (0)

static unsigned long long monotonic(void) {
    struct timespec value;
    need(!clock_gettime(CLOCK_MONOTONIC, &value), "actual monotonic clock");
    return (unsigned long long)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

static struct sockaddr_in address(uint32_t value, unsigned port) {
    return (struct sockaddr_in){
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(value)};
}

static unsigned get16(const unsigned char* bytes) {
    return ((unsigned)bytes[0] << 8) | bytes[1];
}

static void put16(unsigned char* bytes, unsigned value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}

static uint32_t get32(const unsigned char* bytes) {
    return ((uint32_t)get16(bytes) << 16) | get16(bytes + 2);
}

static unsigned checksum(const unsigned char* bytes, size_t length, uint32_t sum) {
    while (length >= 2) {
        sum += get16(bytes);
        bytes += 2;
        length -= 2;
    }
    if (length)
        sum += (unsigned)*bytes << 8;
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (~sum) & 65535;
}

static int opened(int type, int protocol) {
    errno = 0;
    int fd = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
    printf("{\"kind\":\"socket\",\"type\":%d,\"protocol\":%d,\"returncode\":%d,\"errno\":%d}\n",
           type, protocol, fd, fd < 0 ? errno : 0);
    need(fd >= 0, "actual socket creation");
    need((fcntl(fd, F_GETFL) & O_NONBLOCK) && (fcntl(fd, F_GETFD) & FD_CLOEXEC),
         "actual socket flags");
    return fd;
}

static void scalar(int fd, int level, int option, int expected, const char* label) {
    int value = -999;
    socklen_t length = sizeof(value);
    EXPECT(label, getsockopt(fd, level, option, &value, &length), 0, 0);
    printf("{\"kind\":\"scalar\",\"label\":\"%s\",\"value\":%d,\"length\":%u}\n", label, value,
           length);
    need(value == expected && length == sizeof(value), label);
}

static void set(int fd, int level, int option, int value, const char* label) {
    EXPECT(label, setsockopt(fd, level, option, &value, sizeof(value)), 0, 0);
}

static void name(int fd, int peer, uint32_t expected, unsigned port, const char* label) {
    struct sockaddr_in value;
    memset(&value, 0xa5, sizeof(value));
    socklen_t length = sizeof(value);
    EXPECT(label,
           peer ? getpeername(fd, (struct sockaddr*)&value, &length)
                : getsockname(fd, (struct sockaddr*)&value, &length),
           0, 0);
    printf("{\"kind\":\"name\",\"label\":\"%s\",\"family\":%u,\"address\":%u,\"port\":%u,"
           "\"length\":%u}\n",
           label, value.sin_family, ntohl(value.sin_addr.s_addr), ntohs(value.sin_port), length);
    need(length == sizeof(value) && value.sin_family == AF_INET &&
             ntohl(value.sin_addr.s_addr) == expected && ntohs(value.sin_port) == port &&
             !memcmp(value.sin_zero, (unsigned char[8]){0}, 8),
         label);
}

static void bound(int fd, uint32_t value, unsigned port, const char* label) {
    struct sockaddr_in target = address(value, port);
    EXPECT(label, bind(fd, (struct sockaddr*)&target, sizeof(target)), 0, 0);
}

static void quiet(int fd, const char* label) {
    struct pollfd descriptor = {.fd = fd, .events = POLLIN};
    unsigned long long begin = monotonic();
    EXPECT(label, poll(&descriptor, 1, 200), 0, 0);
    unsigned long long end = monotonic();
    printf(
        "{\"kind\":\"quiet\",\"label\":\"%s\",\"begin_ns\":%llu,\"end_ns\":%llu,\"revents\":%u}\n",
        label, begin, end, (unsigned)descriptor.revents);
    need(end - begin >= 200000000ULL && descriptor.revents == 0, label);
    unsigned char byte;
    EXPECT(label, recv(fd, &byte, 1, MSG_DONTWAIT), -1, EAGAIN);
    quiet_windows++;
}

static size_t datagram(unsigned char* bytes, const char* payload, unsigned port) {
    size_t length = strlen(payload);
    put16(bytes, source_port);
    put16(bytes + 2, port);
    put16(bytes + 4, length + 8);
    put16(bytes + 6, 0);
    memcpy(bytes + 8, payload, length);
    return length + 8;
}

static void received(int fd, int raw, uint32_t source, uint32_t destination,
                     const unsigned char* data, size_t length, const char* label) {
    struct pollfd ready = {.fd = fd, .events = POLLIN};
    EXPECT(label, poll(&ready, 1, 2000), 1, 0);
    need(ready.revents & POLLIN, label);
    unsigned char bytes[65536], prefix[12];
    if (raw)
        EXPECT(label, recv(fd, prefix, sizeof(prefix), MSG_PEEK), sizeof(prefix), 0);
    struct sockaddr_in sender;
    memset(&sender, 0xa5, sizeof(sender));
    socklen_t capacity = sizeof(sender);
    errno = 0;
    ssize_t count = recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr*)&sender, &capacity);
    printf("{\"kind\":\"packet\",\"label\":\"%s\",\"raw\":%s,\"returncode\":%ld,\"errno\":%d,"
           "\"family\":%u,\"source\":%u,\"port\":%u,\"length\":%u,\"hex\":\"",
           label, raw ? "true" : "false", (long)count, count < 0 ? errno : 0, sender.sin_family,
           ntohl(sender.sin_addr.s_addr), ntohs(sender.sin_port), capacity);
    static const char digits[] = "0123456789abcdef";
    for (ssize_t at = 0; at < count;) {
        char encoded[512];
        size_t chunk = (size_t)(count - at);
        if (chunk > sizeof(encoded) / 2)
            chunk = sizeof(encoded) / 2;
        for (size_t n = 0; n < chunk; n++) {
            encoded[n * 2] = digits[bytes[at + n] >> 4];
            encoded[n * 2 + 1] = digits[bytes[at + n] & 15];
        }
        need(fwrite(encoded, 2, chunk, stdout) == chunk, "complete actual packet log");
        at += chunk;
    }
    puts("\"}");
    size_t header = raw ? 20 : 0;
    const unsigned char* wanted = raw ? data : data + 8;
    size_t wanted_length = raw ? length : length - 8;
    need(count >= 0 && (size_t)count == header + wanted_length && capacity == sizeof(sender) &&
             sender.sin_family == AF_INET && ntohl(sender.sin_addr.s_addr) == source &&
             ntohs(sender.sin_port) == (raw ? 0 : source_port) &&
             !memcmp(sender.sin_zero, (unsigned char[8]){0}, 8) &&
             !memcmp(bytes + header, wanted, wanted_length),
         label);
    if (raw)
        need(bytes[0] == 0x45 && get16(bytes + 2) == (unsigned)count && bytes[9] == IPPROTO_UDP &&
                 get32(bytes + 12) == source && get32(bytes + 16) == destination &&
                 !checksum(bytes, 20, 0) && !memcmp(prefix, bytes, sizeof(prefix)),
             label);
    quiet(fd, label);
    packets++;
}

static void* invalid_pointer(void) {
    volatile uintptr_t value = 1;
    return (void*)value;
}

static void metadata_and_unicast(void) {
    int icmp = opened(SOCK_RAW, IPPROTO_ICMP);
    scalar(icmp, SOL_SOCKET, SO_PROTOCOL, IPPROTO_ICMP, "icmp-protocol");
    name(icmp, 0, 0, 1, "icmp-initial-name");
    scalar(icmp, SOL_RAW, ICMP_FILTER, 0, "icmp-filter");
    int sender = opened(SOCK_RAW, IPPROTO_UDP);
    scalar(sender, SOL_SOCKET, SO_PROTOCOL, IPPROTO_UDP, "raw-udp-protocol");
    scalar(sender, SOL_SOCKET, SO_TYPE, SOCK_RAW, "raw-udp-type");
    name(sender, 0, 0, IPPROTO_UDP, "raw-udp-initial-name");
    unsigned value = 0;
    socklen_t capacity = sizeof(value);
    EXPECT("raw-udp-get-icmp-filter", getsockopt(sender, SOL_RAW, ICMP_FILTER, &value, &capacity),
           -1, EOPNOTSUPP);
    EXPECT("raw-udp-set-icmp-filter",
           setsockopt(sender, SOL_RAW, ICMP_FILTER, &value, sizeof(value)), -1, EOPNOTSUPP);
    EXPECT("raw-udp-filter-get-invalid-pointers",
           getsockopt(sender, SOL_RAW, ICMP_FILTER, invalid_pointer(), invalid_pointer()), -1,
           EOPNOTSUPP);
    EXPECT("raw-udp-filter-set-invalid-pointer",
           setsockopt(sender, SOL_RAW, ICMP_FILTER, invalid_pointer(), 4), -1, EOPNOTSUPP);
    EXPECT("raw-udp-filter-set-empty-null", setsockopt(sender, SOL_RAW, ICMP_FILTER, NULL, 0), -1,
           EOPNOTSUPP);
    EXPECT("raw-udp-filter-set-negative-length",
           setsockopt(sender, SOL_RAW, ICMP_FILTER, NULL, (socklen_t)-1), -1, EINVAL);
    capacity = (socklen_t)-1;
    EXPECT("raw-udp-filter-get-negative-capacity",
           getsockopt(sender, SOL_RAW, ICMP_FILTER, &value, &capacity), -1, EOPNOTSUPP);
    EXPECT("raw-udp-unknown-get-before-pointer",
           getsockopt(sender, SOL_RAW, 12345, invalid_pointer(), invalid_pointer()), -1,
           ENOPROTOOPT);
    EXPECT("raw-udp-unknown-set-before-pointer",
           setsockopt(sender, SOL_RAW, 12345, invalid_pointer(), 4), -1, ENOPROTOOPT);
    EXPECT("raw-icmp-unknown-get-before-pointer",
           getsockopt(icmp, SOL_RAW, 12345, invalid_pointer(), invalid_pointer()), -1, ENOPROTOOPT);
    EXPECT("raw-icmp-unknown-set-before-pointer",
           setsockopt(icmp, SOL_RAW, 12345, invalid_pointer(), 4), -1, ENOPROTOOPT);
    set(sender, SOL_SOCKET, SO_REUSEADDR, 1, "raw-udp-reuse");
    scalar(sender, SOL_SOCKET, SO_REUSEADDR, 1, "raw-udp-reuse-readback");
    bound(sender, local, 55555, "raw-bind-ignored-port");
    name(sender, 0, local, IPPROTO_UDP, "raw-udp-bound-name");
    struct sockaddr_in peer = address(local, 55556);
    EXPECT("raw-connect", connect(sender, (struct sockaddr*)&peer, sizeof(peer)), 0, 0);
    name(sender, 0, local, IPPROTO_UDP, "raw-udp-connected-name");
    name(sender, 1, local, 55556, "raw-udp-peer-name");
    int receivers[2] = {opened(SOCK_RAW, IPPROTO_UDP), opened(SOCK_RAW, IPPROTO_UDP)};
    int sink = opened(SOCK_DGRAM, 0);
    bound(sink, local, data_port, "udp-sink-bind");
    unsigned char bytes[128];
    size_t length = datagram(bytes, "raw UDP actual full packet", data_port);
    peer = address(local, 55557);
    EXPECT("raw-named-send-ignored-port",
           sendto(sender, bytes, length, 0, (struct sockaddr*)&peer, sizeof(peer)), length, 0);
    received(sink, 0, local, local, bytes, length, "unicast-udp");
    for (unsigned n = 0; n < 2; n++)
        received(receivers[n], 1, local, local, bytes, length, "unicast-raw");
    EXPECT("raw-zero-payload-send", send(sender, bytes, 0, 0), 0, 0);
    for (unsigned n = 0; n < 2; n++)
        received(receivers[n], 1, local, local, bytes, 0, "zero-raw");
    quiet(sink, "zero-UDP-not-delivered");
    length = datagram(bytes, "bad UDP checksum remains raw data", data_port);
    uint32_t pseudo =
        (local >> 16) + (local & 65535) + (local >> 16) + (local & 65535) + 17 + length;
    unsigned sum = checksum(bytes, length, pseudo);
    unsigned invalid = (sum ? sum : 65535) ^ 1;
    put16(bytes + 6, invalid ? invalid : 2);
    need(get16(bytes + 6) && checksum(bytes, length, pseudo), "actually invalid UDP checksum");
    EXPECT("raw-invalid-UDP-checksum-send", send(sender, bytes, length, 0), length, 0);
    for (unsigned n = 0; n < 2; n++)
        received(receivers[n], 1, local, local, bytes, length, "invalid-checksum-raw");
    quiet(sink, "bad-checksum-UDP-not-delivered");
    unsigned char* maximum = malloc(65516);
    need(maximum != NULL, "maximum raw payload allocation");
    put16(maximum, source_port);
    put16(maximum + 2, data_port);
    put16(maximum + 4, 65515);
    put16(maximum + 6, 0);
    for (unsigned n = 8; n < 65516; n++)
        maximum[n] = (unsigned char)(n * 13 + 7);
    EXPECT("maximum-65515-raw-payload-send", send(sender, maximum, 65515, 0), 65515, 0);
    received(sink, 0, local, local, maximum, 65515, "maximum-UDP-payload");
    for (unsigned n = 0; n < 2; n++)
        received(receivers[n], 1, local, local, maximum, 65515, "maximum-raw-packet");
    EXPECT("oversize-65516-raw-payload", send(sender, maximum, 65516, 0), -1, EMSGSIZE);
    free(maximum);
    quiet(icmp, "raw-protocol-isolation");
    EXPECT("close-raw-icmp", close(icmp), 0, 0);
    EXPECT("close-raw-sender", close(sender), 0, 0);
    for (unsigned n = 0; n < 2; n++)
        EXPECT("close-raw-receiver", close(receivers[n]), 0, 0);
    EXPECT("close-UDP-sink", close(sink), 0, 0);
}

static void source_join(int fd) {
    struct ip_mreq_source interest = {.imr_multiaddr.s_addr = htonl(group),
                                      .imr_interface.s_addr = htonl(local),
                                      .imr_sourceaddr.s_addr = htonl(source_a)};
    EXPECT("join-INCLUDE-A",
           setsockopt(fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &interest, sizeof(interest)), 0, 0);
}

static void excluded(int fd) {
    struct ip_mreq interest = {.imr_multiaddr.s_addr = htonl(group),
                               .imr_interface.s_addr = htonl(local)};
    EXPECT("join-EXCLUDE",
           setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &interest, sizeof(interest)), 0, 0);
    struct ip_mreq_source blocked = {.imr_multiaddr.s_addr = htonl(group),
                                     .imr_interface.s_addr = htonl(local),
                                     .imr_sourceaddr.s_addr = htonl(source_a)};
    EXPECT("exclude-source-A",
           setsockopt(fd, IPPROTO_IP, IP_BLOCK_SOURCE, &blocked, sizeof(blocked)), 0, 0);
}

static int multicast_sender(uint32_t source) {
    int fd = opened(SOCK_RAW, IPPROTO_UDP);
    bound(fd, source, 12345, "multicast-sender-source");
    struct in_addr link = {.s_addr = htonl(local)};
    EXPECT("multicast-loopback-interface",
           setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &link, sizeof(link)), 0, 0);
    return fd;
}

static void phase(const char* label, int sender, uint32_t source, int* receivers, unsigned mask) {
    unsigned char bytes[128];
    size_t length = datagram(bytes, label, data_port);
    struct sockaddr_in destination = address(group, 12346);
    EXPECT(label,
           sendto(sender, bytes, length, 0, (struct sockaddr*)&destination, sizeof(destination)),
           length, 0);
    printf("{\"kind\":\"phase\",\"label\":\"%s\",\"source\":%u,\"expected_receivers\":%u}\n", label,
           source, mask);
    for (unsigned n = 0; n < 6; n++) {
        if (receivers[n] < 0)
            continue;
        char channel[80];
        snprintf(channel, sizeof(channel), "%s-receiver%u", label, n);
        if (mask & (1u << n))
            received(receivers[n], n < 4, source, group, bytes, length, channel);
        else
            quiet(receivers[n], channel);
    }
}

static void multicast_lifetime(void) {
    int receivers[6];
    for (unsigned n = 0; n < 6; n++) {
        receivers[n] = opened(n < 4 ? SOCK_RAW : SOCK_DGRAM, n < 4 ? IPPROTO_UDP : 0);
        set(receivers[n], SOL_SOCKET, SO_REUSEADDR, 1, "multicast-reuse");
        set(receivers[n], IPPROTO_IP, IP_MULTICAST_ALL, n == 2, "multicast-all");
        bound(receivers[n], group, n < 4 ? 54321 : data_port, "multicast-group-bind");
    }
    source_join(receivers[0]);
    source_join(receivers[4]);
    excluded(receivers[1]);
    excluded(receivers[5]);
    int first = multicast_sender(source_a), second = multicast_sender(source_b);
    phase("initial-A", first, source_a, receivers, (1u << 0) | (1u << 2) | (1u << 4));
    phase("initial-B", second, source_b, receivers, (1u << 1) | (1u << 2) | (1u << 5));
    int retained = dup(receivers[0]);
    need(retained >= 0, "duplicate INCLUDE description");
    EXPECT("close-original-INCLUDE", close(receivers[0]), 0, 0);
    receivers[0] = retained;
    EXPECT("close-UDP-INCLUDE", close(receivers[4]), 0, 0);
    receivers[4] = -1;
    phase("retained-A", first, source_a, receivers, (1u << 0) | (1u << 2));
    EXPECT("final-INCLUDE-description-close", close(receivers[0]), 0, 0);
    receivers[0] = -1;
    phase("after-final-A", first, source_a, receivers, 0);
    phase("after-final-B", second, source_b, receivers, (1u << 1) | (1u << 2) | (1u << 5));
    receivers[0] = opened(SOCK_RAW, IPPROTO_UDP);
    set(receivers[0], IPPROTO_IP, IP_MULTICAST_ALL, 0, "new-description-no-membership");
    bound(receivers[0], group, 0, "new-description-group-bind");
    phase("new-unjoined-A", first, source_a, receivers, 0);
    source_join(receivers[0]);
    phase("new-joined-A", first, source_a, receivers, (1u << 0) | (1u << 2));
    for (unsigned n = 0; n < 6; n++)
        if (receivers[n] >= 0)
            EXPECT("close-multicast-receiver", close(receivers[n]), 0, 0);
    EXPECT("close-source-A", close(first), 0, 0);
    EXPECT("close-source-B", close(second), 0, 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct utsname identity;
    need(!uname(&identity), "actual kernel identity");
    printf("{\"kind\":\"kernel\",\"sysname\":\"%s\",\"release\":\"%s\"}\n", identity.sysname,
           identity.release);
    metadata_and_unicast();
    multicast_lifetime();
    printf("RAW_UDP_PASS operations=%u packets=%u quiet_windows=%u source_phases=7\n", operations,
           packets, quiet_windows);
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char* phase = "setup";
static unsigned sample;

static void check(int condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "IPV4_TCP_OPTIONS_FAIL uid=%u phase=%s case=%u reason=%s errno=%d\n",
                (unsigned)geteuid(), phase, sample, reason, errno);
        exit(1);
    }
}

static uint16_t get16(const unsigned char* bytes) {
    return (uint16_t)((unsigned)bytes[0] << 8 | bytes[1]);
}

static void put16(unsigned char* bytes, uint16_t value) {
    bytes[0] = (unsigned char)(value >> 8);
    bytes[1] = (unsigned char)value;
}

static uint64_t milliseconds(int clock) {
    struct timespec now;
    check(clock_gettime(clock, &now) == 0, "clock");
    return (uint64_t)now.tv_sec * 1000 + (unsigned long)now.tv_nsec / 1000000;
}

static uint16_t checksum(const unsigned char* bytes, size_t length, uint32_t sum) {
    while (length >= 2) {
        sum += get16(bytes);
        bytes += 2;
        length -= 2;
    }
    if (length)
        sum += (unsigned)*bytes << 8;
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t pseudo(size_t length) {
    return 0x7f00 + 1 + 0x7f00 + 1 + 6 + (uint32_t)length;
}

static void dump(const char* label, const unsigned char* bytes, size_t length) {
    printf("IPV4_TCP_OPTIONS_BYTES uid=%u phase=%s case=%u label=%s length=%zu bytes=",
           (unsigned)geteuid(), phase, sample, label, length);
    for (size_t at = 0; at < length; at++)
        printf("%02x", bytes[at]);
    putchar('\n');
}

static struct sockaddr_in loopback(void) {
    struct sockaddr_in result = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    return result;
}

static uint16_t port(int descriptor) {
    struct sockaddr_in address;
    socklen_t size = sizeof(address);
    check(getsockname(descriptor, (struct sockaddr*)&address, &size) == 0 &&
              size == sizeof(address) && address.sin_family == AF_INET && address.sin_port,
          "socket-port");
    return ntohs(address.sin_port);
}

static int stream(struct sockaddr_in* address) {
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    *address = loopback();
    check(descriptor >= 0 && bind(descriptor, (struct sockaddr*)address, sizeof(*address)) == 0,
          "bound-stream");
    address->sin_port = htons(port(descriptor));
    return descriptor;
}

static size_t option(unsigned kind, unsigned char bytes[40]) {
    memset(bytes, 0, 40);
    if (kind == 0)
        return 0;
    if (kind == 1) {
        memset(bytes, 1, 4);
        return 4;
    }
    if (kind == 2) {
        bytes[0] = 148;
        bytes[1] = 4;
        return 4;
    }
    bytes[0] = kind == 3 ? 7 : 68;
    bytes[1] = kind == 3 ? 31 : kind == 4 ? 32 : 36;
    bytes[2] = kind == 3 ? 4 : 5;
    bytes[3] = kind == 5 ? 1 : 0;
    return kind == 5 ? 36 : 32;
}

static void set_options(int descriptor, unsigned kind) {
    unsigned char bytes[40];
    size_t size = option(kind, bytes);
    check(setsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, bytes, (socklen_t)size) == 0,
          "set-options");
}

static void query(int descriptor, const unsigned char* expected, size_t length) {
    unsigned char bytes[48];
    memset(bytes, 0xa5, sizeof(bytes));
    socklen_t count = sizeof(bytes);
    check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, bytes, &count) == 0, "option-query");
    dump("query", bytes, count);
    check(count == length && !memcmp(bytes, expected, length) && bytes[count] == 0xa5,
          "query-owned-value");
}

static void query_kind(int descriptor, unsigned kind) {
    unsigned char expected[40];
    size_t size = option(kind, expected);
    query(descriptor, expected, size);
}

struct Packet {
    unsigned char bytes[2048];
    size_t length, header;
};

static void drain(int observer) {
    unsigned char bytes[2048];
    while (recv(observer, bytes, sizeof(bytes), 0) >= 0) {
    }
    check(errno == EAGAIN || errno == EWOULDBLOCK, "drain-observer");
}

static void input_checksum(const struct Packet* packet) {
    unsigned char original[60];
    check(packet->header <= sizeof(original), "ip-header-bound");
    memcpy(original, packet->bytes, packet->header);
    // Linux raw input retains the wire checksum after filling a local RR/TS
    // slot. These cases originate with a zero next slot, so undo that one
    // receive update before checking the original header checksum.
    for (size_t at = 20; at < packet->header;) {
        unsigned char* value = original + at;
        if (!*value)
            break;
        if (*value == 1) {
            at++;
            continue;
        }
        check(packet->header - at >= 2 && value[1] >= 2 && value[1] <= packet->header - at,
              "ip-option-bound");
        if (*value == 7 || *value == 68) {
            unsigned advance = *value == 68 && (value[3] & 15) == 1 ? 8 : 4;
            unsigned pointer = value[2];
            check(pointer > advance && pointer - 1 <= value[1], "recorded-input-slot");
            value[2] -= (unsigned char)advance;
            memset(value + value[2] - 1, 0, advance);
        }
        at += value[1];
    }
    check(!checksum(original, packet->header, 0), "original-ip-checksum");
}

static struct Packet wait_for(int observer, uint16_t server, uint16_t client, unsigned flags,
                              unsigned mask, struct Packet* syn, struct Packet* fin) {
    uint64_t deadline = milliseconds(CLOCK_MONOTONIC) + 2000;
    for (;;) {
        uint64_t now = milliseconds(CLOCK_MONOTONIC);
        check(now < deadline, "packet-deadline");
        struct pollfd ready = {.fd = observer, .events = POLLIN};
        check(poll(&ready, 1, (int)(deadline - now)) == 1 && (ready.revents & POLLIN),
              "packet-ready");
        struct Packet packet;
        ssize_t length = recv(observer, packet.bytes, sizeof(packet.bytes), 0);
        if (length < 20)
            continue;
        packet.length = (size_t)length;
        packet.header = 4u * (packet.bytes[0] & 15);
        if (packet.header < 20 || packet.header > packet.length ||
            packet.length - packet.header < 20)
            continue;
        const unsigned char* tcp = packet.bytes + packet.header;
        uint16_t source = get16(tcp), target = get16(tcp + 2);
        if (!((source == server && target == client) || (source == client && target == server)))
            continue;
        check((packet.bytes[0] >> 4) == 4 && packet.bytes[9] == 6 &&
                  get16(packet.bytes + 2) == packet.length,
              "received-ip-header");
        input_checksum(&packet);
        check((size_t)(tcp[12] >> 4) * 4 >= 20 &&
                  (size_t)(tcp[12] >> 4) * 4 <= packet.length - packet.header,
              "received-tcp-header");
        dump("packet", packet.bytes, packet.length);
        if (source == client && target == server) {
            if (syn && (tcp[13] & 0x12) == 2)
                *syn = packet;
            if (fin && (tcp[13] & 1))
                *fin = packet;
        }
        if (source == server && target == client && (tcp[13] & mask) == flags)
            return packet;
    }
}

static void expect_options(const struct Packet* packet, unsigned kind, unsigned visits,
                           uint64_t before, uint64_t after) {
    unsigned char expected[40], actual[40];
    if (kind < 3)
        kind = 0;
    size_t size = option(kind, expected);
    check(packet->header == 20 + size, "response-option-length");
    memcpy(actual, packet->bytes + 20, size);
    if (kind >= 3) {
        unsigned stride = kind == 5 ? 8 : 4;
        expected[2] = (unsigned char)((kind == 3 ? 4 : 5) + stride * visits);
        for (unsigned at = 0; at < visits; at++) {
            unsigned offset = (kind == 3 ? 3 : 4) + at * stride;
            if (kind == 3 || kind == 5) {
                const unsigned char address[] = {127, 0, 0, 1};
                memcpy(expected + offset, address, 4);
                if (kind == 3)
                    continue;
                offset += 4;
            }
            uint32_t stamp = (uint32_t)get16(actual + offset) << 16 | get16(actual + offset + 2);
            uint64_t start = before % 86400000, end = after % 86400000;
            uint64_t delta = (stamp + 86400000 - start + 20) % 86400000;
            uint64_t span = (end + 86400000 - start) % 86400000;
            check(stamp < 86400000 && span < 5000 && delta <= span + 40, "real-response-timestamp");
            memset(actual + offset, 0, 4);
        }
    }
    check(!memcmp(actual, expected, size), "processed-response-options");
}

static void constructors(void) {
    phase = "raw-creation";
    for (unsigned protocol = 1; protocol < 263; protocol++) {
        if (protocol == 255)
            continue; // IPPROTO_RAW uses the distinct IP_HDRINCL contract.
        sample = protocol;
        int descriptor = socket(AF_INET, SOCK_RAW, (int)protocol);
        if (geteuid() == 0) {
            check(descriptor >= 0, "supported-raw-protocol");
            int selected = 0;
            socklen_t length = sizeof(selected);
            check(getsockopt(descriptor, SOL_SOCKET, SO_PROTOCOL, &selected, &length) == 0 &&
                      length == sizeof(selected) && selected == (int)protocol,
                  "retained-raw-protocol");
            check(close(descriptor) == 0, "raw-protocol-close");
        } else
            check(descriptor == -1 && errno == EPERM, "ordinary-raw-creation");
    }
    const int boundaries[] = {-1, 0, 263, 65535};
    for (unsigned at = 0; at < sizeof(boundaries) / sizeof(boundaries[0]); at++) {
        int protocol = boundaries[at];
        int descriptor = socket(AF_INET, SOCK_RAW, protocol);
        check(descriptor == -1 && errno == (protocol == 0 ? EPROTONOSUPPORT : EINVAL),
              "raw-protocol-boundary");
    }
}

static void reset_cases(int observer) {
    phase = "reset";
    for (sample = 0; sample < 6; sample++) {
        drain(observer);
        struct sockaddr_in destination, local;
        int reserved = stream(&destination), client = stream(&local);
        set_options(client, sample);
        uint64_t before = milliseconds(CLOCK_REALTIME);
        check(connect(client, (struct sockaddr*)&destination, sizeof(destination)) == -1 &&
                  errno == ECONNREFUSED,
              "closed-port-refusal");
        struct Packet reply = wait_for(observer, ntohs(destination.sin_port), ntohs(local.sin_port),
                                       4, 4, NULL, NULL);
        check(!checksum(reply.bytes + reply.header, reply.length - reply.header,
                        pseudo(reply.length - reply.header)),
              "reset-tcp-checksum");
        expect_options(&reply, sample, 4, before, milliseconds(CLOCK_REALTIME));
        query_kind(client, sample);
        check(close(client) == 0 && close(reserved) == 0, "reset-close");
    }
}

static void listener_cases(int observer) {
    for (sample = 0; sample < 6; sample++) {
        phase = "listener";
        drain(observer);
        struct sockaddr_in destination, local;
        int server = stream(&destination), client = stream(&local);
        set_options(server, (sample + 2) % 6);
        set_options(client, sample);
        check(listen(server, 1) == 0, "listen");
        uint64_t before = milliseconds(CLOCK_REALTIME);
        check(connect(client, (struct sockaddr*)&destination, sizeof(destination)) == 0, "connect");
        set_options(server, 1);
        int accepted = accept(server, NULL, NULL);
        check(accepted >= 0, "accept");
        struct Packet syn = {0};
        struct Packet reply = wait_for(observer, ntohs(destination.sin_port), ntohs(local.sin_port),
                                       0x12, 0x12, &syn, NULL);
        check(syn.length != 0, "original-syn-observed");
        expect_options(&reply, sample, 4, before, milliseconds(CLOCK_REALTIME));
        size_t child_length = sample >= 3 ? syn.header - 20 : 0;
        query(accepted, syn.bytes + 20, child_length);
        const unsigned char data[] = "tcp-ip-options";
        unsigned char received[sizeof(data)];
        check(send(accepted, data, sizeof(data), 0) == sizeof(data), "accepted-send");
        size_t count = 0;
        while (count < sizeof(received)) {
            ssize_t got = recv(client, received + count, sizeof(received) - count, 0);
            check(got > 0, "accepted-payload-receive");
            count += (size_t)got;
        }
        check(!memcmp(data, received, sizeof(data)), "accepted-payload");
        query(accepted, syn.bytes + 20, child_length);
        query_kind(server, 1);
        set_options(accepted, 2);
        query_kind(server, 1);
        query_kind(accepted, 2);
        drain(observer);
        phase = "close";
        int retained = sample % 2 == 0;
        check((retained ? shutdown(accepted, SHUT_WR) : close(accepted)) == 0 &&
                  recv(client, received, sizeof(received), 0) == 0,
              "active-close-eof");
        check(shutdown(client, SHUT_WR) == 0, "peer-finish");
        struct Packet fin = {0};
        reply = wait_for(observer, ntohs(destination.sin_port), ntohs(local.sin_port), 0x10, 0x3f,
                         NULL, &fin);
        check(fin.length && (fin.bytes[fin.header + 13] & 1), "original-peer-fin");
        check(close(client) == 0, "peer-close");
        drain(observer);
        phase = retained ? "time-wait-retained" : "time-wait-compacted";
        unsigned kind = sample == 3 ? 4 : 3;
        set_options(observer, kind);
        size_t length = fin.length - fin.header;
        unsigned char segment[256];
        check(length <= sizeof(segment), "original-fin-bounds");
        memcpy(segment, fin.bytes + fin.header, length);
        put16(segment + 16, 0);
        put16(segment + 16, checksum(segment, length, pseudo(length)));
        dump("replayed-fin", segment, length);
        before = milliseconds(CLOCK_REALTIME);
        destination.sin_port = 0;
        check(sendto(observer, segment, length, 0, (struct sockaddr*)&destination,
                     sizeof(destination)) == (ssize_t)length,
              "actual-fin-replay");
        reply = wait_for(observer, port(server), ntohs(local.sin_port), 0x10, 0x3f, NULL, NULL);
        check(!checksum(reply.bytes + reply.header, reply.length - reply.header,
                        pseudo(reply.length - reply.header)),
              "time-wait-tcp-checksum");
        expect_options(&reply, kind, 4, before, milliseconds(CLOCK_REALTIME));
        set_options(observer, 0);
        if (retained)
            check(close(accepted) == 0, "retained-time-wait-close");
        check(close(server) == 0, "listener-close");
    }
}

static void cases(int observer) {
    constructors();
    reset_cases(observer);
    listener_cases(observer);
    printf("IPV4_TCP_OPTIONS_SCOPE_PASS uid=%u reset_cases=6 listener_cases=6 time_wait_cases=6 "
           "time_wait_retained=3 time_wait_compacted=3 raw_protocols=261\n",
           (unsigned)geteuid());
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    check(geteuid() == 0, "root-observer");
    const char* runtime = getenv("IPV4_OPTIONS_RUNTIME_FD");
    if (runtime) {
        char* end;
        long descriptor = strtol(runtime, &end, 10);
        unsigned char release;
        check(*runtime && !*end && descriptor >= 0 && descriptor <= INT32_MAX &&
                  read((int)descriptor, &release, 1) == 1 && release == 1 &&
                  close((int)descriptor) == 0,
              "runtime-observer");
    }
    int observer = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
    struct sockaddr_in address = loopback();
    check(observer >= 0 && bind(observer, (struct sockaddr*)&address, sizeof(address)) == 0,
          "tcp-observer");
    cases(observer);
    pid_t child = fork();
    check(child >= 0, "fork");
    if (!child) {
        check(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0,
              "ordinary-credentials");
        cases(observer);
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "ordinary-completion");
    check(close(observer) == 0, "observer-close");
    puts("IPV4_TCP_OPTIONS_PASS scopes=2 cases=36");
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <netinet/in.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *protocol = "setup", *sample = "setup";

static void check(int condition, const char* stage) {
    if (!condition) {
        fprintf(stderr, "IPV4_OPTIONS_FAIL protocol=%s sample=%s stage=%s uid=%u errno=%d\n",
                protocol, sample, stage, (unsigned)geteuid(), errno);
        exit(1);
    }
}

static size_t decode(const char* text, unsigned char* bytes) {
    if (!strcmp(text, "-"))
        return 0;
    size_t length = strlen(text);
    check(length <= 80 && length % 2 == 0, "fixture-hex-length");
    for (size_t index = 0; index < length; index += 2) {
        unsigned value;
        check(sscanf(text + index, "%2x", &value) == 1, "fixture-hex-value");
        bytes[index / 2] = (unsigned char)value;
    }
    return length / 2;
}

static void seed(int descriptor) {
    const unsigned char bytes[4] = {1, 1, 1, 1};
    check(setsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, bytes, sizeof(bytes)) == 0, "seed");
}

static void seeded_value(int descriptor) {
    unsigned char value[8];
    memset(value, 0xa5, sizeof(value));
    socklen_t count = sizeof(value);
    check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, value, &count) == 0 && count == 4 &&
              value[0] == 1 && value[1] == 1 && value[2] == 1 && value[3] == 1 && value[4] == 0xa5,
          "unchanged-seed");
}

static void pointer_order(int descriptor) {
    sample = "pointer-order";
    seed(descriptor);
    check(setsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, (void*)(uintptr_t)1, 41) == -1 &&
              errno == EINVAL,
          "oversize-before-copy");
    seeded_value(descriptor);
    check(setsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, (void*)(uintptr_t)1, (socklen_t)-1) ==
                  -1 &&
              errno == EINVAL,
          "negative-before-copy");
    seeded_value(descriptor);
    check(setsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, (void*)(uintptr_t)1, 4) == -1 &&
              errno == EFAULT,
          "setter-copy-fault");
    seeded_value(descriptor);
    socklen_t count = 40;
    check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, (void*)(uintptr_t)1, &count) == -1 &&
              errno == EFAULT && count == 4,
          "length-before-value-fault");
    unsigned char buffer[8];
    memset(buffer, 0xa5, sizeof(buffer));
    count = (socklen_t)-1;
    check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, buffer, &count) == -1 && errno == EINVAL &&
              count == (socklen_t)-1 && buffer[0] == 0xa5,
          "negative-query-capacity");
    check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, buffer, (socklen_t*)(uintptr_t)1) == -1 &&
              errno == EFAULT && buffer[0] == 0xa5,
          "length-fault-before-value");
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && mprotect(pages + 4096, 4096, PROT_NONE) == 0, "guard-page");
    memset(pages + 4094, 0xa5, 2);
    count = 40;
    check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, pages + 4094, &count) == -1 &&
              errno == EFAULT && count == 4 && pages[4094] == 1 && pages[4095] == 1,
          "query-accessible-prefix");
    check(setsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, pages + 4094, 4) == -1 && errno == EFAULT,
          "setter-prefix-does-not-publish");
    seeded_value(descriptor);
    const unsigned char original_length[] = {8, 3, 2, 1};
    const unsigned char returned_length[] = {4, 0, 0, 0};
    for (unsigned prefix = 0; prefix < 4; prefix++) {
        check(mprotect(pages + 4096, 4096, PROT_READ | PROT_WRITE) == 0, "length-page-writable");
        unsigned char* length_bytes = pages + 4096 - prefix;
        memcpy(length_bytes, original_length, 4);
        memset(buffer, 0xa5, sizeof(buffer));
        check(mprotect(pages + 4096, 4096, PROT_READ) == 0, "length-page-readonly");
        check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, buffer, (socklen_t*)length_bytes) ==
                      -1 &&
                  errno == EFAULT,
              "length-store-fault");
        for (unsigned at = 0; at < 4; at++)
            check(length_bytes[at] == (at < prefix ? returned_length[at] : original_length[at]),
                  "length-store-native-prefix");
        for (unsigned at = 0; at < sizeof(buffer); at++)
            check(buffer[at] == 0xa5, "length-store-before-value");
    }
    check(munmap(pages, 8192) == 0, "guard-release");
    check(setsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, (void*)(uintptr_t)1, 0) == 0,
          "clear-ignores-pointer");
    count = 40;
    check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, (void*)(uintptr_t)1, &count) == 0 &&
              count == 0,
          "empty-query-ignores-pointer");
}

static void corpus(int descriptor, FILE* stream, unsigned privileged) {
    check(fseek(stream, 0, SEEK_SET) == 0, "rewind-fixture");
    unsigned observed = 0;
    char line[384], name[128], input_text[81], output_text[81];
    while (fgets(line, sizeof(line), stream)) {
        unsigned raw;
        int expected;
        check(strchr(line, '\n') != NULL && sscanf(line, "%127s %u %80s %d %80s", name, &raw,
                                                   input_text, &expected, output_text) == 5,
              "fixture-record");
        if (raw != privileged)
            continue;
        sample = name;
        unsigned char input[40], expected_bytes[40], output[48];
        size_t length = decode(input_text, input),
               expected_length = decode(output_text, expected_bytes);
        seed(descriptor);
        int result = setsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, input, (socklen_t)length);
        result = result < 0 ? -errno : result;
        if (result != expected)
            fprintf(stderr, "IPV4_OPTIONS_RESULT actual=%d expected=%d\n", result, expected);
        check(result == expected, "setter-native-result");
        memset(output, 0xa5, sizeof(output));
        socklen_t count = sizeof(output);
        check(getsockopt(descriptor, IPPROTO_IP, IP_OPTIONS, output, &count) == 0 &&
                  count == expected_length && !memcmp(output, expected_bytes, expected_length) &&
                  output[count] == 0xa5,
              "normalized-native-query");
        ++observed;
    }
    sample = "completion";
    check(!ferror(stream) && observed == 7110, "complete-corpus");
    pointer_order(descriptor);
    printf("IPV4_OPTIONS_SCOPE_PASS protocol=%s privileged=%u observations=%u\n", protocol,
           privileged, observed);
}

static uint32_t utc_milliseconds(void) {
    struct timespec now;
    check(clock_gettime(CLOCK_REALTIME, &now) == 0, "realtime");
    return (uint32_t)((now.tv_sec % 86400) * 1000 + now.tv_nsec / 1000000);
}

static uint32_t be32(const unsigned char* bytes) {
    return (uint32_t)bytes[0] << 24 | (uint32_t)bytes[1] << 16 | (uint32_t)bytes[2] << 8 | bytes[3];
}

static void loopback_wire(void) {
    protocol = "udp-wire";
    sample = "loopback";
    int sender = socket(AF_INET, SOCK_DGRAM, 0), receiver = socket(AF_INET, SOCK_DGRAM, 0);
    check(sender >= 0 && receiver >= 0, "wire-sockets");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t address_length = sizeof(address);
    check(bind(receiver, (struct sockaddr*)&address, sizeof(address)) == 0 &&
              getsockname(receiver, (struct sockaddr*)&address, &address_length) == 0,
          "wire-bind");
    int enabled = 1, ttl = 63, tos = 34;
    for (unsigned option = 0; option < 5; option++) {
        const int names[] = {IP_PKTINFO, IP_RECVTTL, IP_RECVTOS, IP_RECVOPTS, IP_RETOPTS};
        check(setsockopt(receiver, IPPROTO_IP, names[option], &enabled, sizeof(enabled)) == 0,
              "receive-option-enable");
        int value = 0;
        socklen_t length = sizeof(value);
        check(getsockopt(receiver, IPPROTO_IP, names[option], &value, &length) == 0 &&
                  length == sizeof(value) && value == 1,
              "receive-option-query");
    }
    check(setsockopt(sender, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == 0 &&
              setsockopt(sender, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == 0,
          "wire-header-defaults");
    unsigned loopback = if_nametoindex("lo");
    check(loopback != 0, "loopback-index");
    for (unsigned kind = 0; kind < 8; kind++) {
        char wire_sample[32];
        snprintf(wire_sample, sizeof(wire_sample), "case-%u", kind);
        sample = wire_sample;
        unsigned char options[40] = {0}, expected[40] = {0};
        size_t length = 0;
        unsigned stamps[2] = {0}, stamp_count = 0;
        if (kind == 1) {
            memset(options, 1, 4);
            length = 4;
        } else if (kind == 2 || kind == 7) {
            options[0] = 148;
            options[1] = 4;
            length = 4;
        } else if (kind == 3) {
            options[0] = 7;
            options[1] = 15;
            options[2] = 4;
            length = 16;
        } else if (kind == 4 || kind == 6) {
            options[0] = 68;
            options[1] = 16;
            options[2] = 5;
            length = 16;
            stamps[0] = 4;
            stamps[1] = 8;
            stamp_count = 2;
            if (kind == 6) {
                options[16] = 7;
                options[17] = 7;
                options[18] = 4;
                length = 24;
            }
        } else if (kind == 5) {
            options[0] = 68;
            options[1] = 20;
            options[2] = 5;
            options[3] = 1;
            length = 20;
            stamps[0] = 8;
            stamps[1] = 16;
            stamp_count = 2;
        }
        check(setsockopt(sender, IPPROTO_IP, IP_OPTIONS, options, (socklen_t)length) == 0,
              "wire-option-set");
        unsigned char payload[16] = {'I', 'P', 'O', 'P', 'T', '_', 'W', 'I', 'R', 'E'};
        payload[15] = (unsigned char)kind;
        struct iovec send_vector = {payload, sizeof(payload)};

        union {
            struct cmsghdr alignment;
            unsigned char bytes[CMSG_SPACE(40)];
        } send_control;

        memset(&send_control, 0, sizeof(send_control));
        struct msghdr sent = {.msg_name = &address,
                              .msg_namelen = sizeof(address),
                              .msg_iov = &send_vector,
                              .msg_iovlen = 1};
        if (kind == 7) {
            sent.msg_control = send_control.bytes;
            sent.msg_controllen = CMSG_SPACE(16);
            struct cmsghdr* header = CMSG_FIRSTHDR(&sent);
            header->cmsg_level = IPPROTO_IP;
            header->cmsg_type = IP_RETOPTS;
            header->cmsg_len = CMSG_LEN(16);
            unsigned char record[16] = {7, 15, 4};
            memcpy(CMSG_DATA(header), record, sizeof(record));
        }
        uint32_t before = utc_milliseconds();
        check(sendmsg(sender, &sent, 0) == sizeof(payload), "wire-sendmsg");
        struct pollfd ready = {.fd = receiver, .events = POLLIN};
        check(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN), "wire-receive-ready");
        unsigned char data[32];
        struct iovec vector = {data, sizeof(data)};

        union {
            struct cmsghdr alignment;
            unsigned char bytes[512];
        } controls;

        memset(&controls, 0xa5, sizeof(controls));
        struct msghdr received = {.msg_iov = &vector,
                                  .msg_iovlen = 1,
                                  .msg_control = controls.bytes,
                                  .msg_controllen = sizeof(controls.bytes)};
        check(recvmsg(receiver, &received, 0) == sizeof(payload) && !received.msg_flags &&
                  !memcmp(data, payload, sizeof(payload)),
              "wire-delivered-payload");
        uint32_t after = utc_milliseconds();
        unsigned char queried[48];
        memset(queried, 0xa5, sizeof(queried));
        socklen_t query_length = sizeof(queried);
        check(getsockopt(sender, IPPROTO_IP, IP_OPTIONS, queried, &query_length) == 0 &&
                  query_length == length && !memcmp(queried, options, length) &&
                  queried[length] == 0xa5,
              "wire-preserves-description");
        if (kind == 7) {
            memset(expected, 0, sizeof(expected));
            expected[0] = 7;
            expected[1] = 15;
            expected[2] = 12;
            length = 16;
        } else {
            memcpy(expected, options, length);
            if (kind == 3)
                expected[2] = 12;
            if (kind == 4 || kind == 6)
                expected[2] = 13;
            if (kind == 5)
                expected[2] = 21;
            if (kind == 6)
                expected[18] = 8;
        }
        const unsigned char local[] = {127, 0, 0, 1};
        if (kind == 3 || kind == 7) {
            memcpy(expected + 3, local, 4);
            memcpy(expected + 7, local, 4);
        }
        if (kind == 5) {
            memcpy(expected + 4, local, 4);
            memcpy(expected + 12, local, 4);
        }
        if (kind == 6)
            memcpy(expected + 19, local, 4);
        unsigned seen = 0;
        unsigned char processed[40] = {0};
        const int order[] = {IP_PKTINFO, IP_TTL, IP_TOS, IP_RECVOPTS, IP_RETOPTS};
        size_t control_at = 0;
        // Inspect the serialized ABI directly: some libc CMSG_NXTHDR macros
        // stop before an otherwise valid empty control at the end of a buffer.
        while (control_at + sizeof(struct cmsghdr) <= received.msg_controllen) {
            struct cmsghdr* header = (struct cmsghdr*)(controls.bytes + control_at);
            check(header->cmsg_len >= CMSG_LEN(0) &&
                      header->cmsg_len <= received.msg_controllen - control_at,
                  "wire-control-bounds");
            check(seen < (length ? 5u : 3u) && header->cmsg_level == IPPROTO_IP &&
                      header->cmsg_type == order[seen],
                  "wire-control-order");
            size_t count = header->cmsg_len - CMSG_LEN(0);
            const unsigned char* bytes = CMSG_DATA(header);
            if (seen == 0) {
                struct in_pktinfo info;
                check(count == sizeof(info), "wire-pktinfo-size");
                memcpy(&info, bytes, sizeof(info));
                check((unsigned)info.ipi_ifindex == loopback &&
                          info.ipi_spec_dst.s_addr == htonl(INADDR_LOOPBACK) &&
                          info.ipi_addr.s_addr == htonl(INADDR_LOOPBACK),
                      "wire-pktinfo");
            } else if (seen == 1) {
                int value;
                check(count == sizeof(value), "wire-ttl-size");
                memcpy(&value, bytes, sizeof(value));
                check(value == ttl, "wire-ttl");
            } else if (seen == 2)
                check(count == 1 && *bytes == tos, "wire-tos");
            else if (seen == 3) {
                check(count == length, "wire-option-length");
                memcpy(processed, bytes, count);
                unsigned char normalized[40];
                memcpy(normalized, bytes, count);
                for (unsigned at = 0; at < stamp_count; at++) {
                    uint32_t value = be32(bytes + stamps[at]);
                    uint32_t delta = (value + 86400000 - before + 20) % 86400000;
                    uint32_t span = (after + 86400000 - before) % 86400000;
                    check(value < 86400000 && span < 5000 && delta <= span + 40,
                          "wire-actual-timestamp");
                    memset(normalized + stamps[at], 0, 4);
                }
                check(!memcmp(normalized, expected, length), "wire-processed-options");
            } else {
                size_t returned = kind == 1 || kind == 2 ? 0 : length;
                unsigned char expected_return[40] = {0};
                if (kind == 6) {
                    memcpy(expected_return, processed + 16, 7);
                    memcpy(expected_return + 7, processed, 16);
                } else
                    memcpy(expected_return, processed, returned);
                check(count == returned && !memcmp(bytes, expected_return, count),
                      "wire-return-options");
            }
            seen++;
            control_at += CMSG_ALIGN(header->cmsg_len);
        }
        check(control_at == received.msg_controllen, "wire-control-consumed");
        if (seen != (length ? 5u : 3u))
            fprintf(stderr, "IPV4_OPTIONS_CONTROLS case=%u observed=%u expected=%u bytes=%zu\n",
                    kind, seen, length ? 5u : 3u, (size_t)received.msg_controllen);
        check(seen == (length ? 5u : 3u), "wire-complete-controls");
    }
    sample = "completion";
    check(close(sender) == 0 && close(receiver) == 0, "wire-close");
    printf("IPV4_OPTIONS_WIRE_PASS cases=8 uid=%u actual_payload timestamps return_order "
           "per_message\n",
           (unsigned)geteuid());
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    check(argc == 2 && geteuid() == 0, "root-fixture");
    const char* runtime = getenv("IPV4_OPTIONS_RUNTIME_FD");
    if (runtime) {
        char* end;
        long descriptor = strtol(runtime, &end, 10);
        unsigned char release;
        check(*runtime && !*end && descriptor >= 0 && descriptor <= INT32_MAX &&
                  read((int)descriptor, &release, 1) == 1 && release == 1 &&
                  close((int)descriptor) == 0,
              "native-runtime-observer");
    }
    FILE* table = fopen(argv[1], "r");
    check(table != NULL, "open-fixture");
    const int types[] = {SOCK_DGRAM, SOCK_STREAM, SOCK_RAW};
    const char* names[] = {"udp", "tcp", "raw"};
    for (unsigned index = 0; index < 3; ++index) {
        protocol = names[index];
        sample = "create";
        int descriptor = socket(AF_INET, types[index], types[index] == SOCK_RAW ? IPPROTO_ICMP : 0);
        check(descriptor >= 0, "socket");
        corpus(descriptor, table, 1);
        if (index == 0)
            loopback_wire();
        protocol = names[index];
        pid_t child = fork();
        check(child >= 0, "fork");
        if (!child) {
            check(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0,
                  "ordinary-credentials");
            corpus(descriptor, table, 0);
            if (index == 0)
                loopback_wire();
            _exit(0);
        }
        int status;
        check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "ordinary-completion");
        check(close(descriptor) == 0, "final-close");
    }
    check(fclose(table) == 0, "close-fixture");
    puts("IPV4_OPTIONS_PASS protocols=3 observations=42660 scopes=6");
    return 0;
}

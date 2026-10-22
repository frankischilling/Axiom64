// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_EXTENSION_WIRE"
#define IPV6_BARRIER_PROTOCOL 0x88c1
#define IPV6_BARRIER_MAGIC "IP6X"
#include "ipv6_fixture.h"

static void append(unsigned char* bytes, size_t* used, int type, const void* data, size_t size) {
    size_t length = CMSG_SPACE(size);
    check(*used + length <= 256, "bounded extension controls");
    memset(bytes + *used, 0, length);
    struct cmsghdr header = {.cmsg_len = CMSG_LEN(size), .cmsg_level = 41, .cmsg_type = type};
    memcpy(bytes + *used, &header, sizeof(header));
    memcpy(bytes + *used + sizeof(header), data, size);
    *used += length;
}

static void scalar(unsigned char* bytes, size_t* used, int type, int value) {
    append(bytes, used, type, &value, sizeof(value));
}

static void extension(unsigned char* bytes, size_t* used, int type, unsigned length, unsigned value,
                      int malformed) {
    unsigned char data[16] = {250, length / 8 - 1, 0x1e, length - 4};
    memset(data + 4, value, length - 4);
    if (malformed)
        data[1]++;
    append(bytes, used, type, data, length);
}

static int error_for(unsigned variant) {
    return variant == 10                                     ? EMSGSIZE
           : variant == 13                                   ? EPERM
           : variant == 11 || variant == 12 || variant == 14 ? EINVAL
                                                             : 0;
}

static void output(unsigned lane) {
    unsigned char* payload = malloc(16384);
    unsigned char* original_payload = malloc(16384);
    check(payload && original_payload, "owned extension payload");
    barrier(lane, 0);
    for (unsigned sequence = 0; sequence < 64; sequence++) {
        unsigned variant = sequence % 16, scope = sequence / 16 % 2;
        unsigned named = (variant + scope) % 2;
        int type = SOCK_DGRAM + sequence / 32;
        unsigned length = variant == 9 ? 16384 : variant == 8 || variant == 10 ? 2048 : 128;
        int fd = wire_socket(lane, type, 49000 + lane + scope * 10,
                             type == SOCK_RAW ? 58 : 50000 + lane + scope * 10, scope);
        option(fd, 41, IPV6_UNICAST_HOPS, 37);
        option(fd, 41, IPV6_TCLASS, 0x25);
        option(fd, 41, IPV6_DONTFRAG, variant == 8 || variant == 9);
        option(fd, SOL_SOCKET, SO_SNDBUF, 65536);
        int alias = dup(fd);
        check(alias >= 0, "shared extension description");
        for (unsigned n = 0; n < length; n++)
            payload[n] = n * 23 + sequence * 13 + lane;
        if (type == SOCK_RAW) {
            payload[0] = 129;
            payload[1] = payload[2] = payload[3] = 0;
        }
        memcpy(original_payload, payload, length);
        unsigned char ancillary[256], original_ancillary[256];
        memset(ancillary, 0xa5, sizeof(ancillary));
        size_t used = 0;
        struct in6_pktinfo info = {.ipi6_addr = address(lane, 2, 0, scope).sin6_addr,
                                   .ipi6_ifindex = indices[lane]};
        append(ancillary, &used, IPV6_PKTINFO, &info, sizeof(info));
        scalar(ancillary, &used, IPV6_HOPLIMIT, 47);
        scalar(ancillary, &used, IPV6_TCLASS, 0xcd);
        unsigned header_length = variant == 7 || variant == 9 ? 16 : 8;
        if (variant == 3 || variant == 4)
            extension(ancillary, &used, 59, 8, 0x11, 0);
        if (variant == 6 || variant == 15)
            extension(ancillary, &used, 55, 8, 0x33, 0);
        if (variant != 1 && variant != 4 && variant != 6)
            extension(ancillary, &used, variant == 5 ? 3 : 54, header_length, 0x44, variant == 12);
        if (variant != 0 && variant != 6 && variant != 11 && variant != 12 && variant != 14)
            extension(ancillary, &used, variant == 5 ? 4 : 59, header_length, 0x55, 0);
        if (variant == 11 || variant == 14)
            extension(ancillary, &used, variant == 14 ? 3 : 54, 8, 0x66, 0);
        if (variant == 8 || variant == 9 || variant == 10)
            scalar(ancillary, &used, IPV6_DONTFRAG, variant == 10);
        memcpy(original_ancillary, ancillary, sizeof(ancillary));
        struct sockaddr_in6 target =
            address(lane, variant == 9 ? 160 + sequence : 1,
                    type == SOCK_RAW ? 58 : 50000 + lane + scope * 10, scope);
        if (variant == 9)
            connect_address(alias, target);
        struct iovec vectors[] = {{payload, 3}, {payload + 3, length - 3}};
        struct msghdr message = {.msg_name = named ? &target : NULL,
                                 .msg_namelen = named ? sizeof(target) : 0,
                                 .msg_iov = vectors,
                                 .msg_iovlen = 2,
                                 .msg_control = ancillary,
                                 .msg_controllen = used,
                                 .msg_flags = 0x5a5a};
        struct msghdr original_message = message;
        struct iovec original_vectors[2];
        memcpy(original_vectors, vectors, sizeof(vectors));
        struct sockaddr_in6 original_target = target;
        barrier(lane, sequence * 2 + 1);
        long result;
        int error;
        if (variant == 13) {
            int channel[2];
            check(!pipe(channel), "ordinary-user result channel");
            pid_t child = fork();
            check(child >= 0, "ordinary-user held description");
            if (!child) {
                check(!close(channel[0]) && !setgid(65534) && !setuid(65534),
                      "drop extension sender privileges");
                errno = 0;
                long actual = sendmsg(alias, &message, MSG_DONTWAIT);
                int actual_error = actual < 0 ? errno : 0;
                check(!memcmp(payload, original_payload, length) &&
                          !memcmp(ancillary, original_ancillary, sizeof(ancillary)) &&
                          !memcmp(vectors, original_vectors, sizeof(vectors)) &&
                          !memcmp(&message, &original_message, sizeof(message)) &&
                          !memcmp(&target, &original_target, sizeof(target)),
                      "ordinary-user original extension inputs");
                long observation[2] = {actual, actual_error};
                check(write(channel[1], observation, sizeof(observation)) == sizeof(observation),
                      "ordinary-user original result");
                _exit(0);
            }
            check(!close(channel[1]), "close parent result writer");
            long observation[2];
            check(read(channel[0], observation, sizeof(observation)) == sizeof(observation),
                  "read actual ordinary-user result");
            int status;
            check(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                      !WEXITSTATUS(status) && !close(channel[0]),
                  "complete ordinary-user check");
            result = observation[0];
            error = observation[1];
        } else {
            errno = 0;
            result = sendmsg(alias, &message, MSG_DONTWAIT);
            error = result < 0 ? errno : 0;
        }
        printf("IPV6_EXTENSION_WIRE_CASE lane=%u case=%u type=%d scope=%u variant=%u named=%u "
               "bytes=%u result=%ld errno=%d length=%zu hops=%d class=%d df=%d control=",
               lane, sequence, type, scope, variant, named, length, result, error, used,
               get(fd, 41, IPV6_UNICAST_HOPS), get(alias, 41, IPV6_TCLASS),
               get(fd, 41, IPV6_DONTFRAG));
        for (unsigned n = 0; n < sizeof(ancillary); n++)
            printf("%02x", ancillary[n]);
        puts("");
        fflush(stdout);
        int wanted = error_for(variant);
        check(wanted ? result == -1 && error == wanted : result == length,
              "original extension send result");
        check(!memcmp(payload, original_payload, length) &&
                  !memcmp(ancillary, original_ancillary, sizeof(ancillary)) &&
                  !memcmp(vectors, original_vectors, sizeof(vectors)) &&
                  !memcmp(&message, &original_message, sizeof(message)) &&
                  !memcmp(&target, &original_target, sizeof(target)),
              "all original extension inputs unchanged");
        check(get(fd, 41, IPV6_UNICAST_HOPS) == 37 && get(alias, 41, IPV6_TCLASS) == 0x25 &&
                  get(fd, 41, IPV6_DONTFRAG) == (variant == 8 || variant == 9),
              "extension send preserves shared scalar options");
        memset(payload, 0xa5, length);
        memset(ancillary, 0xa5, sizeof(ancillary));
        memset(vectors, 0xa5, sizeof(vectors));
        memset(&message, 0xa5, sizeof(message));
        memset(&target, 0xa5, sizeof(target));
        if (variant == 9) {
            option(alias, 41, IPV6_UNICAST_HOPS, 99);
            option(fd, 41, IPV6_TCLASS, 7);
            option(alias, 41, IPV6_DONTFRAG, 1);
        }
        check(!close(alias) && !close(fd), "retire queued extension owners");
        int reused = create(type);
        if (variant == 9)
            barrier(lane, 193 + sequence / 16);
        barrier(lane, sequence * 2 + 2);
        check(!get(reused, SOL_SOCKET, SO_ERROR) && !close(reused),
              "queued extension output preserves reused description");
    }
    free(original_payload);
    free(payload);
    printf("IPV6_EXTENSION_WIRE_PASS lane=%u cases=64 variants=16 scopes=2 transports=2\n", lane);
}

int ipv6_extension_wire(const unsigned* input_indices, const unsigned char* input_macs,
                        const int* input_packets) {
    for (unsigned lane = 0; lane < 2; lane++) {
        indices[lane] = input_indices[lane];
        memcpy(macs[lane], input_macs + lane * 6, 6);
        packets[lane] = input_packets[lane];
    }
    for (unsigned lane = 0; lane < 2; lane++)
        output(lane);
    puts("IPV6_EXTENSION_WIRE_DONE adapters=2 cases=128 variants=16 scopes=2 transports=2");
    return 0;
}

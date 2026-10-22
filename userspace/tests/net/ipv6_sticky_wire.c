// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_STICKY_WIRE"
#define IPV6_BARRIER_PROTOCOL 0x88c3
#define IPV6_BARRIER_MAGIC "IP6S"
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
    return variant == 10                    ? EMSGSIZE
           : variant == 14                  ? EPERM
           : variant == 11 || variant == 12 ? EINVAL
                                            : 0;
}

static unsigned route_header(unsigned char* bytes, unsigned mode, unsigned lane, unsigned scope,
                             struct in6_addr first) {
    unsigned length = mode == 1 ? 40 : mode == 3 ? 64 : 24;
    memset(bytes, 0, 64);
    bytes[0] = 250;
    bytes[1] = length / 8 - 1;
    bytes[2] = mode ? 4 : 2;
    bytes[3] = mode == 2 ? 0 : mode == 3 ? 2 : 1;
    bytes[4] = mode ? bytes[3] : 0x71;
    bytes[5] = mode ? 0 : 0x72;
    bytes[6] = 0x73;
    bytes[7] = 0x74;
    for (unsigned n = 0; n <= (mode ? bytes[4] : 0); n++) {
        struct in6_addr value = address(lane, 77 + n, 0, scope).sin6_addr;
        memcpy(bytes + 8 + n * 16, &value, sizeof(value));
    }
    memcpy(bytes + 8 + (mode ? bytes[3] * 16 : 0), &first, sizeof(first));
    if (mode == 3) {
        bytes[56] = 0x1e;
        bytes[57] = 6;
        memset(bytes + 58, 0x9a, 6);
    }
    return length;
}

static void stored_header(int fd, unsigned type, unsigned value) {
    unsigned char bytes[8] = {250, 0, 0x1e, 4, value, value, value, value};
    check(!setsockopt(fd, 41, type, bytes, sizeof(bytes)), "store original sticky header");
    memset(bytes, 0xa5, sizeof(bytes));
}

static size_t saved_headers(int fd, unsigned char* bytes) {
    static const unsigned types[] = {54, 55, 57, 59};
    memset(bytes, 0xa5, 160);
    size_t used = 0;
    for (unsigned n = 0; n < 4; n++) {
        unsigned char header[80];
        memset(header, 0xa5, sizeof(header));
        socklen_t length = sizeof(header);
        check(!getsockopt(fd, 41, types[n], header, &length) && length <= sizeof(header),
              "actual shared sticky getter");
        check(used + 2 + length <= 160, "bounded complete sticky state");
        bytes[used++] = length;
        bytes[used++] = length >> 8;
        memcpy(bytes + used, header, length);
        used += length;
    }
    return used;
}

static void output(unsigned lane) {
    unsigned char* payload = malloc(16384);
    unsigned char* original_payload = malloc(16384);
    check(payload && original_payload, "owned extension payload");
    barrier(lane, 0);
    for (unsigned sequence = 0; sequence < 80; sequence++) {
        unsigned variant = sequence % 20, scope = sequence / 20 % 2;
        unsigned named = (variant + scope) % 2;
        int type = SOCK_DGRAM + sequence / 40;
        unsigned length = variant == 9 ? 16384 : variant == 8 || variant == 10 ? 2048 : 128;
        int fd = wire_socket(lane, type, 53000 + lane + scope * 10,
                             type == SOCK_RAW ? 58 : 54000 + lane + scope * 10, scope);
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
        unsigned mode =
            variant == 1 || variant == 9 || variant == 10 || variant == 13 || variant == 14 ? 1
            : variant == 2                                                                  ? 2
            : variant == 3 || variant == 8                                                  ? 3
                                                                                            : 0;
        struct in6_addr first =
            address(lane, variant == 9 ? 240 + sequence / 20 * 4 : 1, 0, scope).sin6_addr;
        stored_header(fd, 54, 0x11);
        stored_header(alias, 55, 0x22);
        stored_header(fd, 59, 0x55);
        unsigned char routing[64];
        unsigned route_length = route_header(routing, mode, lane, scope, first);
        check(!setsockopt(alias, 41, 57, routing, route_length),
              "store complete sticky Routing header");
        memset(routing, 0xa5, sizeof(routing));
        if (variant == 15) {
            static const unsigned types[] = {54, 55, 57, 59};
            for (unsigned n = 0; n < 4; n++)
                check(!setsockopt(alias, 41, types[n], NULL, 0),
                      "remove all shared sticky headers");
        } else if (variant == 16) {
            check(!setsockopt(alias, 41, 57, NULL, 0), "remove only shared Routing header");
        } else if (variant == 17) {
            stored_header(alias, 59, 0x66);
        } else if (variant == 19) {
            check(!setsockopt(alias, 41, 54, NULL, 0) && !setsockopt(fd, 41, 59, NULL, 0),
                  "retain pre-Destination and Routing without other sticky headers");
        }
        int replace_error = 0;
        if (variant == 18) {
            route_length = route_header(routing, 0, lane, scope, first);
            routing[2] = 0;
            errno = 0;
            check(setsockopt(alias, 41, 57, routing, route_length) == -1 && errno == EINVAL,
                  "invalid replacement preserves previous sticky state");
            replace_error = errno;
            memset(routing, 0xa5, sizeof(routing));
        }
        if (variant == 4 || variant == 12) {
            route_length = route_header(routing, variant == 12 ? 1 : 0, lane, scope, first);
            if (variant == 4) {
                routing[4] = 0x81;
                routing[5] = 0x82;
                routing[6] = 0x83;
                routing[7] = 0x84;
            }
            append(ancillary, &used, 57, routing, route_length);
        } else if (variant == 5) {
            extension(ancillary, &used, 59, 8, 0x66, 0);
        } else if (variant == 6 || variant == 11 || variant == 14) {
            extension(ancillary, &used, 54, 8, 0x44, variant == 11);
        } else if (variant == 7) {
            extension(ancillary, &used, 55, 8, 0x33, 0);
        }
        if (variant == 8 || variant == 9 || variant == 10)
            scalar(ancillary, &used, IPV6_DONTFRAG, variant == 10);
        unsigned char original_sticky[160], actual_sticky[160];
        size_t sticky_length = saved_headers(alias, original_sticky);
        memcpy(original_ancillary, ancillary, sizeof(ancillary));
        struct sockaddr_in6 target =
            address(lane, 71, type == SOCK_RAW ? 58 : 54000 + lane + scope * 10, scope);
        int routed = variant != 5 && variant != 6 && variant != 7 && variant != 15 && variant != 16;
        if (routed && !scope)
            check(inet_pton(AF_INET6, lane ? "2001:db8:92::47" : "2001:db8:91::47",
                            &target.sin6_addr) == 1,
                  "off-route final destination");
        // Connect uses the stored first hop, even if this send's ancillary
        // headers temporarily select a different chain.
        if (!named)
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
        struct sockaddr_in6 original_target = target, original_local, original_peer;
        socklen_t name_length = sizeof(original_local);
        check(!getsockname(alias, (struct sockaddr*)&original_local, &name_length) &&
                  name_length == sizeof(original_local),
              "original routed local identity");
        name_length = sizeof(original_peer);
        check(!getpeername(alias, (struct sockaddr*)&original_peer, &name_length) &&
                  name_length == sizeof(original_peer),
              "original routed connected identity");
        barrier(lane, sequence * 2 + 1);
        long result;
        int error;
        if (variant == 13 || variant == 14) {
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
        printf("IPV6_STICKY_WIRE_CASE lane=%u case=%u type=%d scope=%u variant=%u named=%u "
               "bytes=%u result=%ld errno=%d length=%zu hops=%d class=%d df=%d replace_errno=%d "
               "control=",
               lane, sequence, type, scope, variant, named, length, result, error, used,
               get(fd, 41, IPV6_UNICAST_HOPS), get(alias, 41, IPV6_TCLASS),
               get(fd, 41, IPV6_DONTFRAG), replace_error);
        for (unsigned n = 0; n < sizeof(ancillary); n++)
            printf("%02x", ancillary[n]);
        check(saved_headers(fd, actual_sticky) == sticky_length &&
                  !memcmp(actual_sticky, original_sticky, sizeof(actual_sticky)),
              "every original sticky byte survives the per-message call");
        printf(" sticky=");
        for (unsigned n = 0; n < sizeof(actual_sticky); n++)
            printf("%02x", actual_sticky[n]);
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
        struct sockaddr_in6 actual;
        name_length = sizeof(actual);
        check(!getsockname(alias, (struct sockaddr*)&actual, &name_length) &&
                  name_length == sizeof(actual) &&
                  !memcmp(&actual, &original_local, sizeof(actual)),
              "routed control preserves local identity");
        name_length = sizeof(actual);
        check(!getpeername(alias, (struct sockaddr*)&actual, &name_length) &&
                  name_length == sizeof(actual) && !memcmp(&actual, &original_peer, sizeof(actual)),
              "routing preserves final connected peer identity");
        memset(payload, 0xa5, length);
        memset(ancillary, 0xa5, sizeof(ancillary));
        memset(vectors, 0xa5, sizeof(vectors));
        memset(&message, 0xa5, sizeof(message));
        memset(&target, 0xa5, sizeof(target));
        if (variant == 9) {
            option(alias, 41, IPV6_UNICAST_HOPS, 99);
            option(fd, 41, IPV6_TCLASS, 7);
            option(alias, 41, IPV6_DONTFRAG, 1);
            static const unsigned types[] = {54, 55, 57, 59};
            for (unsigned n = 0; n < 4; n++)
                check(!setsockopt(alias, 41, types[n], NULL, 0),
                      "release shared sticky allocations after queueing");
        }
        check(!close(alias) && !close(fd), "retire queued extension owners");
        int reused = create(type);
        unsigned char empty[160];
        check(saved_headers(reused, empty) == 8, "reused description has no sticky allocation");
        for (unsigned n = 0; n < 8; n++)
            check(!empty[n], "reused description has no stale sticky option");
        if (variant == 9)
            barrier(lane, 193 + sequence / 20);
        barrier(lane, sequence * 2 + 2);
        check(!get(reused, SOL_SOCKET, SO_ERROR) && !close(reused),
              "queued extension output preserves reused description");
    }
    free(original_payload);
    free(payload);
    printf("IPV6_STICKY_WIRE_PASS lane=%u cases=80 variants=20 scopes=2 transports=2\n", lane);
}

int ipv6_sticky_wire(const unsigned* input_indices, const unsigned char* input_macs,
                     const int* input_packets) {
    for (unsigned lane = 0; lane < 2; lane++) {
        indices[lane] = input_indices[lane];
        memcpy(macs[lane], input_macs + lane * 6, 6);
        packets[lane] = input_packets[lane];
    }
    for (unsigned lane = 0; lane < 2; lane++)
        output(lane);
    puts("IPV6_STICKY_WIRE_DONE adapters=2 cases=160 variants=20 scopes=2 transports=2");
    return 0;
}

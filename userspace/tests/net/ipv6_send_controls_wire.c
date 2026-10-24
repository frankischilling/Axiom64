// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_SEND_WIRE"
#define IPV6_BARRIER_PROTOCOL 0x88c0
#define IPV6_BARRIER_MAGIC "IP6W"
#include "ipv6_fixture.h"

static void append(unsigned char* bytes, size_t* used, int type, const void* value, size_t size) {
    size_t length = CMSG_SPACE(size);
    check(*used + length <= 192, "bounded owned ancillary input");
    memset(bytes + *used, 0, length);
    struct cmsghdr header = {
        .cmsg_len = CMSG_LEN(size), .cmsg_level = IPPROTO_IPV6, .cmsg_type = type};
    memcpy(bytes + *used, &header, sizeof(header));
    memcpy(bytes + *used + sizeof(header), value, size);
    *used += length;
}

static void scalar(unsigned char* bytes, size_t* used, int type, int value) {
    append(bytes, used, type, &value, sizeof(value));
}

static int expected_error(unsigned variant) {
    if (variant == 7)
        return EMSGSIZE;
    if (variant == 13)
        return ENODEV;
    if (variant == 20)
        return EFAULT;
    return (variant >= 14 && variant <= 21) || variant == 23 ? EINVAL : 0;
}

static void output(unsigned lane) {
    unsigned char* payload = malloc(16384);
    unsigned char* original_payload = malloc(16384);
    void* guard = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(payload && original_payload && guard != MAP_FAILED,
          "owned payload and protected control");
    barrier(lane, 0);
    for (unsigned sequence = 0; sequence < 96; sequence++) {
        unsigned variant = sequence % 24, scoped = sequence / 24 % 2;
        int type = SOCK_DGRAM + sequence / 48;
        unsigned length = variant == 8 ? 16384 : variant == 6 || variant == 7 ? 2048 : 128;
        int fd = wire_socket(lane, type, 47000 + lane + scoped * 10,
                             type == SOCK_RAW ? 58 : 48000 + lane + scoped * 10, scoped);
        if (variant == 13)
            check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "", 1),
                  "unbound device for unknown-index admission");
        option(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 33);
        option(fd, IPPROTO_IPV6, IPV6_TCLASS, 18);
        option(fd, IPPROTO_IPV6, IPV6_DONTFRAG, variant == 6 || variant == 8);
        option(fd, SOL_SOCKET, SO_SNDBUF, 65536);
        int alias = dup(fd);
        check(alias >= 0, "shared output-control description");
        for (unsigned n = 0; n < length; n++)
            payload[n] = n * 19 + sequence * 11 + lane;
        if (type == SOCK_RAW) {
            payload[0] = 129;
            payload[1] = payload[2] = payload[3] = 0;
        }
        memcpy(original_payload, payload, length);
        unsigned char ancillary[192], original_ancillary[192];
        memset(ancillary, 0xa5, sizeof(ancillary));
        size_t used = 0;
        struct in6_pktinfo info = {.ipi6_addr = address(lane, 2, 0, scoped).sin6_addr,
                                   .ipi6_ifindex = indices[lane]};
        if (variant == 2)
            info.ipi6_ifindex = 0;
        if (variant == 3)
            memset(&info.ipi6_addr, 0, sizeof(info.ipi6_addr));
        if (variant == 13)
            info.ipi6_ifindex = 0x7ffffffe;
        if (variant == 14)
            info.ipi6_addr = address(lane, 77, 0, scoped).sin6_addr;
        if (variant == 15)
            info.ipi6_addr = in6addr_loopback;
        if (variant == 22)
            info.ipi6_addr = address(lane ^ 1, 2, 0, 0).sin6_addr;
        if (variant == 23) {
            memset(&info.ipi6_addr, 0, sizeof(info.ipi6_addr));
            info.ipi6_ifindex = indices[lane ^ 1];
        }
        if ((variant >= 1 && variant <= 3) || variant == 8 || variant == 13 || variant == 14 ||
            variant == 15 || variant == 22 || variant == 23)
            append(ancillary, &used, IPV6_PKTINFO, &info, sizeof(info));
        if (variant == 4 || variant == 8 || variant == 12 || variant == 19 || variant == 21)
            scalar(ancillary, &used, IPV6_HOPLIMIT, 43);
        if (variant == 5 || variant == 8 || variant == 12)
            scalar(ancillary, &used, IPV6_TCLASS, 0xab);
        if (variant == 6 || variant == 8)
            scalar(ancillary, &used, IPV6_DONTFRAG, 0);
        if (variant == 7)
            scalar(ancillary, &used, IPV6_DONTFRAG, 1);
        if (variant == 9)
            scalar(ancillary, &used, IPV6_HOPLIMIT, 0);
        if (variant == 10) {
            scalar(ancillary, &used, IPV6_HOPLIMIT, 255);
            scalar(ancillary, &used, IPV6_TCLASS, 255);
        }
        if (variant == 11) {
            scalar(ancillary, &used, IPV6_HOPLIMIT, -1);
            scalar(ancillary, &used, IPV6_TCLASS, -1);
        }
        if (variant == 12) {
            scalar(ancillary, &used, IPV6_HOPLIMIT, 44);
            scalar(ancillary, &used, IPV6_TCLASS, 0xac);
        }
        if (variant == 16)
            scalar(ancillary, &used, IPV6_HOPLIMIT, 256);
        if (variant == 17)
            scalar(ancillary, &used, IPV6_TCLASS, 256);
        if (variant == 18)
            scalar(ancillary, &used, IPV6_DONTFRAG, 2);
        size_t capacity = variant == 19 ? 19 : variant == 20 ? 20 : used;
        if (variant == 21)
            ((struct cmsghdr*)ancillary)->cmsg_len = 15;
        memcpy(original_ancillary, ancillary, sizeof(ancillary));
        struct sockaddr_in6 target =
            address(lane, 1, type == SOCK_RAW ? 58 : 48000 + lane + scoped * 10, scoped);
        if (variant == 8) {
            target = address(lane, 100 + sequence,
                             type == SOCK_RAW ? 58 : 48000 + lane + scoped * 10, scoped);
            check(!connect(alias, (struct sockaddr*)&target, sizeof(target)),
                  "queued control destination has no resolved neighbor");
        }
        if (variant == 13)
            target.sin6_scope_id = 0;
        struct iovec vectors[] = {{payload, 1}, {payload + 1, length - 1}};
        struct msghdr message = {.msg_name = variant & 1 ? &target : NULL,
                                 .msg_namelen = variant & 1 ? sizeof(target) : 0,
                                 .msg_iov = vectors,
                                 .msg_iovlen = 2,
                                 .msg_control = variant == 20 ? guard : ancillary,
                                 .msg_controllen = capacity,
                                 .msg_flags = 0x5a5a};
        struct msghdr original_message = message;
        struct iovec original_vectors[2];
        memcpy(original_vectors, vectors, sizeof(vectors));
        struct sockaddr_in6 original_target = target, local_name, peer_name;
        socklen_t name_length = sizeof(local_name);
        check(!getsockname(fd, (struct sockaddr*)&local_name, &name_length) &&
                  name_length == sizeof(local_name),
              "original local name");
        name_length = sizeof(peer_name);
        check(!getpeername(fd, (struct sockaddr*)&peer_name, &name_length) &&
                  name_length == sizeof(peer_name),
              "original connected peer");
        barrier(lane, 2 * sequence + 1);
        errno = 0;
        // Musl walks control headers before entering the kernel. Exercise the protected
        // pointer through the Linux syscall so this case checks kernel EFAULT admission.
        long result = variant == 20 ? syscall(SYS_sendmsg, alias, &message, MSG_DONTWAIT)
                                    : sendmsg(alias, &message, MSG_DONTWAIT);
        int error = result < 0 ? errno : 0, wanted = expected_error(variant);
        printf("IPV6_SEND_WIRE_CASE lane=%u case=%u type=%d scope=%u variant=%u named=%u "
               "bytes=%u result=%ld errno=%d length=%zu hops=%d class=%d df=%d control=",
               lane, sequence, type, scoped, variant, variant & 1, length, result, error, capacity,
               get(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS), get(fd, IPPROTO_IPV6, IPV6_TCLASS),
               get(fd, IPPROTO_IPV6, IPV6_DONTFRAG));
        for (unsigned n = 0; n < sizeof(ancillary); n++)
            printf("%02x", ancillary[n]);
        puts("");
        fflush(stdout);
        check(wanted ? result == -1 && error == wanted : result == length,
              "actual per-message output result");
        check(!memcmp(payload, original_payload, length) &&
                  !memcmp(ancillary, original_ancillary, sizeof(ancillary)) &&
                  !memcmp(vectors, original_vectors, sizeof(vectors)) &&
                  !memcmp(&message, &original_message, sizeof(message)) &&
                  !memcmp(&target, &original_target, sizeof(target)),
              "complete original send inputs remain unchanged");
        check(get(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS) == 33 &&
                  get(alias, IPPROTO_IPV6, IPV6_TCLASS) == 18 &&
                  get(fd, IPPROTO_IPV6, IPV6_DONTFRAG) == (variant == 6 || variant == 8),
              "per-message policy does not mutate shared options");
        struct sockaddr_in6 actual;
        name_length = sizeof(actual);
        check(!getsockname(alias, (struct sockaddr*)&actual, &name_length) &&
                  name_length == sizeof(actual) && !memcmp(&actual, &local_name, sizeof(actual)),
              "per-message source does not replace local binding");
        name_length = sizeof(actual);
        check(!getpeername(alias, (struct sockaddr*)&actual, &name_length) &&
                  name_length == sizeof(actual) && !memcmp(&actual, &peer_name, sizeof(actual)),
              "per-message destination preserves connected name");
        memset(payload, 0xa5, length);
        memset(ancillary, 0xa5, sizeof(ancillary));
        memset(vectors, 0xa5, sizeof(vectors));
        memset(&message, 0xa5, sizeof(message));
        memset(&target, 0xa5, sizeof(target));
        if (variant == 8) {
            option(alias, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 99);
            option(fd, IPPROTO_IPV6, IPV6_TCLASS, 7);
            option(alias, IPPROTO_IPV6, IPV6_DONTFRAG, 1);
        }
        check(!close(alias) && !close(fd), "retire every queued control owner");
        int reused = create(type);
        if (variant == 8) {
            // The peer withholds neighbor resolution until every borrowed input is
            // overwritten, shared options are changed and both owners are closed.
            barrier(lane, 193 + sequence / 24);
        }
        barrier(lane, 2 * sequence + 2);
        check(!get(reused, SOL_SOCKET, SO_ERROR) && !close(reused),
              "retired output cannot affect a reused description");
    }
    check(!munmap(guard, 4096), "release protected control");
    free(original_payload);
    free(payload);
    printf("IPV6_SEND_WIRE_PASS lane=%u cases=96 scopes=2 variants=24\n", lane);
}

int ipv6_send_controls_wire(const unsigned* input_indices, const unsigned char* input_macs,
                            const int* input_packets) {
    int query = socket(AF_INET, SOCK_DGRAM, 0);
    check(query >= 0, "output interface identity query");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(query, SIOCGIFINDEX, &request) &&
                  (unsigned)request.ifr_ifindex == input_indices[lane],
              "actual output interface index");
        check(!ioctl(query, SIOCGIFHWADDR, &request) &&
                  !memcmp(request.ifr_hwaddr.sa_data, input_macs + lane * 6, 6),
              "actual output interface MAC");
        indices[lane] = input_indices[lane];
        memcpy(macs[lane], input_macs + lane * 6, 6);
        packets[lane] = input_packets[lane];
        printf("IPV6_SEND_WIRE_INTERFACE lane=%u index=%u\n", lane, indices[lane]);
    }
    for (unsigned lane = 0; lane < 2; lane++)
        output(lane);
    check(!close(query), "release interface identity query");
    puts("IPV6_SEND_WIRE_DONE adapters=2 cases=192 variants=24 scopes=2 transports=2");
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_ERROR_METADATA"
#define IPV6_BARRIER_PROTOCOL 0x88be
#define IPV6_BARRIER_MAGIC "IP6M"
#include "ipv6_fixture.h"
#include "ipv6_error_record.h"

static void receive_options(int fd, unsigned mask, unsigned outer) {
    const int options[] = {IPV6_RECVPKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS,
                           IPV6_RECVHOPOPTS, IPV6_RECVRTHDR,    IPV6_RECVDSTOPTS};
    for (unsigned at = 0; at < (outer ? 6u : 3u); at++) {
        option(fd, IPPROTO_IPV6, options[at], !!(mask & (1u << at)));
        check(get(fd, IPPROTO_IPV6, options[at]) == !!(mask & (1u << at)),
              "shared error receive options");
    }
}

static void run(unsigned lane, unsigned outer) {
    const char* label = outer ? "IPV6_ERROR_EXTENSIONS" : "IPV6_ERROR_METADATA";
    unsigned protocol = outer ? 0x88c4 : IPV6_BARRIER_PROTOCOL;
    const char* magic = outer ? "IP6X" : IPV6_BARRIER_MAGIC;
    unsigned char* control_pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char* name_pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char* header_pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(control_pages != MAP_FAILED && name_pages != MAP_FAILED && header_pages != MAP_FAILED &&
              !mprotect(control_pages + 4096, 4096, PROT_NONE) &&
              !mprotect(name_pages + 4096, 4096, PROT_NONE),
          "owned wire metadata guards");
    ethernet_barrier(lane, 0, protocol, magic, label);
    for (unsigned sequence = 0; sequence < 80; sequence++) {
        unsigned variant = sequence % 20, scoped = sequence / 20 % 2;
        unsigned kind = sequence >= 40 ? SOCK_RAW : SOCK_DGRAM;
        unsigned all = outer ? 63 : 7;
        unsigned mask = variant < 8 ? variant * (outer ? 9 : 1) : variant == 12 ? 0 : all;
        int fd = create(kind), alias = dup(fd);
        check(alias >= 0, "wire metadata alias");
        char device[16];
        snprintf(device, sizeof(device), "eth%u", lane);
        check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1),
              "wire metadata device");
        option(fd, IPPROTO_IPV6, IPV6_RECVERR, 1);
        option(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 33 + sequence);
        if (kind == SOCK_RAW) {
            struct icmp6_filter filter;
            ICMP6_FILTER_SETBLOCKALL(&filter);
            check(!setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)),
                  "normal raw queue remains independent of error delivery");
        } else
            option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        bind_address(fd, address(lane, 2, kind == SOCK_DGRAM ? 46000 + sequence : 0, scoped));
        connect_address(
            fd, address(lane, 128 + sequence, kind == SOCK_DGRAM ? 48000 + sequence : 58, scoped));
        receive_options(fd, variant == 11 ? 0 : variant == 12 ? all : mask, outer);
        unsigned char sent[32], payload[32], drain[32], name[40], control[384];
        for (unsigned at = 0; at < sizeof(sent); at++)
            sent[at] = sequence * 7 + lane * 13 + at * 19;
        if (kind == SOCK_RAW) {
            sent[0] = 129;
            sent[1] = sent[2] = sent[3] = 0;
            sent[4] = 0x6d;
            sent[5] = 0x45;
            sent[6] = sequence >> 8;
            sent[7] = sequence;
        }
        check(send(fd, sent, sizeof(sent), 0) == sizeof(sent), "actual original error input");
        ethernet_barrier(lane, 2 * sequence + 1, protocol, magic, label);
        readable(fd, POLLERR);
        check(get(fd, SOL_SOCKET, SO_ERROR) == ECONNREFUSED, "original remote port error");
        struct pollfd pending = {.fd = fd, .events = POLLERR};
        check(poll(&pending, 1, 0) == 1 && pending.revents & POLLERR,
              "queued error survives clearing pending error");
        if (variant == 11 || variant == 12)
            receive_options(alias, mask, outer);
        memset(payload, 0xa5, sizeof(payload));
        memset(drain, 0xa5, sizeof(drain));
        memset(name, 0xa5, sizeof(name));
        memset(control, 0xa5, sizeof(control));
        memset(control_pages, 0xa5, 4096);
        memset(name_pages, 0xa5, 4096);
        check(!mprotect(header_pages + 4096, 4096, PROT_READ | PROT_WRITE),
              "prepare result header");
        memset(header_pages, 0xa5, 8192);
        unsigned control_visible = variant == 14   ? 143
                                   : variant == 18 ? 17
                                                   : (outer ? sizeof(control) : 192);
        unsigned char* output_control =
            variant == 14 || variant == 18 ? control_pages + 4096 - control_visible : control;
        unsigned name_visible = variant == 16 ? 1 : 0;
        unsigned char* output_name = variant == 19  ? NULL
                                     : name_visible ? name_pages + 4096 - name_visible
                                                    : name;
        unsigned capacity = variant == 8    ? 16
                            : variant == 9  ? 36
                            : variant == 10 ? 88
                            : outer         ? 384
                                            : 192;
        unsigned payload_size = variant == 13 ? 8 : sizeof(payload);
        struct iovec vectors[] = {
            {payload, 5}, {variant == 15 ? name_pages + 4096 : payload + 5, payload_size - 5}};
        struct msghdr before;
        memset(&before, 0xa5, sizeof(before));
        before.msg_name = output_name;
        before.msg_namelen = sizeof(name);
        before.msg_iov = vectors;
        before.msg_iovlen = 2;
        before.msg_control = output_control;
        before.msg_controllen = capacity;
        before.msg_flags = 0x5a5a;
        uint64_t count = 2, full_capacity = capacity;
        memcpy((unsigned char*)&before + 24, &count, sizeof(count));
        memcpy((unsigned char*)&before + 40, &full_capacity, sizeof(full_capacity));
        unsigned char* header = header_pages + 4096 - (variant == 17 ? 48 : 56);
        memcpy(header, &before, sizeof(before));
        check(!mprotect(header_pages + 4096, 4096, PROT_READ), "protected result stores");
        unsigned flags = MSG_ERRQUEUE | MSG_DONTWAIT;
        if (variant == 12 || variant == 18)
            flags |= MSG_PEEK;
        if (variant == 13)
            flags |= MSG_TRUNC;
        if (variant == 19)
            flags |= MSG_CMSG_CLOEXEC;
        errno = 0;
        long result = syscall(SYS_recvmsg, fd, header, flags);
        int error = result < 0 ? errno : 0;
        struct msghdr after;
        memcpy(&after, header, sizeof(after));
        struct iovec vector = {.iov_base = drain, .iov_len = sizeof(drain)};
        struct msghdr empty = {.msg_iov = &vector, .msg_iovlen = 1};
        errno = 0;
        long queued = recvmsg(fd, &empty, MSG_ERRQUEUE | MSG_DONTWAIT);
        int queue_error = queued < 0 ? errno : 0;
        errno = 0;
        long normal = recv(fd, drain, sizeof(drain), MSG_DONTWAIT);
        int normal_error = normal < 0 ? errno : 0;
        struct metadata_record record = {.label = label,
                                         .lane = lane,
                                         .sequence = sequence,
                                         .kind = kind,
                                         .scoped = scoped,
                                         .variant = variant,
                                         .mask = mask,
                                         .capacity = capacity,
                                         .input_flags = flags,
                                         .result = result,
                                         .queued = queued,
                                         .normal = normal,
                                         .error = error,
                                         .queue_error = queue_error,
                                         .normal_error = normal_error,
                                         .control_visible = control_visible,
                                         .name_visible = name_visible,
                                         .before = &before,
                                         .after = &after,
                                         .name = name,
                                         .name_prefix = output_name,
                                         .control = output_control,
                                         .payload = payload,
                                         .drain = drain};
        check(!emit_metadata_record(&record), "complete error metadata record");
        check(queued == -1 && queue_error == EAGAIN && normal == -1 && normal_error == EAGAIN &&
                  !get(fd, SOL_SOCKET, SO_ERROR) && poll(&pending, 1, 0) == 0,
              "checksum rejection, error dequeue and normal queue independence");
        ethernet_barrier(lane, 2 * sequence + 2, protocol, magic, label);
        check(!close(alias) && !close(fd), "retire metadata descriptions");
    }
    check(!munmap(control_pages, 8192) && !munmap(name_pages, 8192) && !munmap(header_pages, 8192),
          "release wire metadata guards");
    printf("%s_WIRE_PASS lane=%u cases=80 scopes=2 variants=20\n", label, lane);
}

int ipv6_error_metadata_wire(const unsigned* input_indices, const unsigned char* input_macs,
                             const int* input_packets) {
    int query = socket(AF_INET, SOCK_DGRAM, 0);
    check(query >= 0, "metadata interface query");
    for (unsigned lane = 0; lane < 2; lane++) {
        struct ifreq request = {0};
        snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
        check(!ioctl(query, SIOCGIFINDEX, &request) &&
                  (unsigned)request.ifr_ifindex == input_indices[lane],
              "actual metadata interface index");
        check(!ioctl(query, SIOCGIFHWADDR, &request) &&
                  !memcmp(request.ifr_hwaddr.sa_data, input_macs + lane * 6, 6),
              "actual interface MAC");
        indices[lane] = input_indices[lane];
        memcpy(macs[lane], input_macs + lane * 6, 6);
        packets[lane] = input_packets[lane];
        printf("IPV6_ERROR_METADATA_INTERFACE lane=%u index=%u\n", lane, indices[lane]);
    }
    for (unsigned lane = 0; lane < 2; lane++)
        run(lane, 0);
    for (unsigned lane = 0; lane < 2; lane++)
        run(lane, 1);
    check(!close(query), "release metadata interface query");
    puts("IPV6_ERROR_METADATA_PASS adapters=2 cases=160 variants=20 scopes=2 transports=2");
    puts("IPV6_ERROR_EXTENSIONS_PASS adapters=2 cases=160 variants=20 scopes=2 transports=2");
    return 0;
}

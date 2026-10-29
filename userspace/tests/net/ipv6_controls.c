// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_CONTROLS"
#define IPV6_BARRIER_PROTOCOL 0x88bd
#define IPV6_BARRIER_MAGIC "IP6C"
#include "ipv6_fixture.h"
#include <stddef.h>

_Static_assert(sizeof(struct msghdr) == 56, "Linux x86-64 message header");
_Static_assert(offsetof(struct msghdr, msg_controllen) == 40, "Linux control length");

int ipv6_controls_local(void);
int ipv6_controls_name_faults(void);
int ipv6_controls_header_faults(void);

static void bytes(const void* data, size_t size) {
    const unsigned char* value = data;
    for (size_t at = 0; at < size; at++)
        printf("%02x", value[at]);
}

static void controls(int fd, unsigned mask) {
    const int names[] = {IPV6_RECVPKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS};
    for (unsigned n = 0; n < 3; n++)
        option(fd, IPPROTO_IPV6, names[n], !!(mask & (1U << n)));
}

static unsigned char* guard(void) {
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED, "metadata guard pages");
    return pages;
}

static void run(unsigned lane) {
    unsigned char *control_pages = guard(), *name_pages = guard(), *header_pages = guard();
    check(!mprotect(control_pages + 4096, 4096, PROT_NONE) &&
              !mprotect(name_pages + 4096, 4096, PROT_NONE),
          "metadata copy guards");
    printf("IPV6_CONTROLS_INTERFACE lane=%u index=%u\n", lane, indices[lane]);
    for (unsigned sequence = 0; sequence < 80; sequence++) {
        unsigned variant = sequence % 20, scoped = sequence / 20 % 2;
        unsigned kind = sequence / 40 ? SOCK_RAW : SOCK_DGRAM;
        unsigned mask = variant < 8 ? variant : 7;
        int fd = wire_socket(lane, kind, kind == SOCK_RAW ? 0 : 41000 + sequence,
                             kind == SOCK_RAW ? 58 : 42000 + sequence, scoped);
        if (kind == SOCK_RAW) {
            struct icmp6_filter filter;
            ICMP6_FILTER_SETBLOCKALL(&filter);
            ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
            check(!setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)),
                  "metadata raw input ownership");
        }
        int alias = dup(fd);
        check(alias >= 0, "metadata description alias");
        controls(fd, mask ^ 7);
        barrier(lane, 2 * sequence + 1);
        readable(fd, POLLIN);
        // Toggle through the alias only after the original datagram is queued.
        controls(alias, mask);
        unsigned char control[96], payload[32], drain[32], name[40];
        memset(control, 0xa5, sizeof(control));
        memset(payload, 0xa5, sizeof(payload));
        memset(drain, 0xa5, sizeof(drain));
        memset(name, 0xa5, sizeof(name));
        memset(control_pages, 0xa5, 4096);
        memset(name_pages, 0xa5, 4096);
        check(!mprotect(header_pages + 4096, 4096, PROT_READ | PROT_WRITE),
              "prepare result header");
        memset(header_pages, 0xa5, 8192);
        unsigned visible_control = variant == 14 ? 37 : variant == 18 ? 17 : sizeof(control);
        unsigned char* output_control =
            variant == 14 || variant == 18 ? control_pages + 4096 - visible_control : control;
        unsigned name_prefix = variant == 16 ? 1 : 0;
        unsigned char* output_name = name_prefix ? name_pages + 4096 - name_prefix : name;
        size_t capacity = variant == 8    ? 16
                          : variant == 9  ? 36
                          : variant == 10 ? 56
                          : variant == 11 ? 88
                                          : sizeof(control);
        size_t payload_size = variant == 13 ? 8 : sizeof(payload);
        struct iovec vectors[] = {
            {payload, 5}, {variant == 15 ? name_pages + 4096 : payload + 5, payload_size - 5}};
        struct msghdr before;
        memset(&before, 0xa5, sizeof(before));
        before.msg_name = output_name;
        before.msg_namelen = variant == 19 ? 0 : sizeof(name);
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
        check(!mprotect(header_pages + 4096, 4096, PROT_READ), "readable header write guard");
        unsigned flags = variant == 12 || variant == 18 ? MSG_PEEK : 0;
        if (variant == 13)
            flags |= MSG_TRUNC;
        errno = 0;
        long result = syscall(SYS_recvmsg, fd, header, MSG_DONTWAIT | flags);
        int error = result < 0 ? errno : 0;
        struct msghdr after;
        memcpy(&after, header, sizeof(after));
        errno = 0;
        long queued = recv(fd, drain, sizeof(drain), MSG_DONTWAIT);
        int queue_error = queued < 0 ? errno : 0;
        printf("IPV6_CONTROLS_CASE lane=%u case=%u kind=%u scope=%u variant=%u mask=%u "
               "capacity=%zu input_flags=%u result=%ld errno=%d name_length=%u length=%zu "
               "flags=%u queued=%ld queue_errno=%d control_visible=%u name_visible=%u "
               "before_header=",
               lane, sequence, kind, scoped, variant, mask, capacity, flags, result, error,
               after.msg_namelen, (size_t)after.msg_controllen, (unsigned)after.msg_flags, queued,
               queue_error, visible_control, name_prefix);
        bytes(&before, sizeof(before));
        printf(" header=");
        bytes(&after, sizeof(after));
        printf(" name=");
        bytes(name, sizeof(name));
        printf(" name_prefix=");
        bytes(output_name, name_prefix);
        printf(" control=");
        bytes(output_control, visible_control);
        printf(" payload=");
        bytes(payload, sizeof(payload));
        printf(" drain=");
        bytes(drain, sizeof(drain));
        puts("");
        fflush(stdout);
        struct pollfd pending = {.fd = fd, .events = POLLIN};
        check(poll(&pending, 1, 0) == 0, "metadata checksum and dequeue ownership");
        barrier(lane, 2 * sequence + 2);
        check(!close(alias) && !close(fd), "metadata description retirement");
    }
    check(!munmap(control_pages, 8192) && !munmap(name_pages, 8192) && !munmap(header_pages, 8192),
          "release metadata guards");
    printf("IPV6_CONTROLS_WIRE_PASS lane=%u cases=80 scopes=2 variants=20\n", lane);
}

int main(void) {
    check(!ipv6_controls_local() && !ipv6_controls_name_faults() && !ipv6_controls_header_faults(),
          "complete local control and result-copy observations");
    int control = fixture_interfaces();
    for (unsigned lane = 0; lane < 2; lane++)
        run(lane);
    check(!close(control), "release metadata interface control");
    for (unsigned lane = 0; lane < 2; lane++)
        check(!close(packets[lane]), "release metadata Ethernet socket");
    puts("IPV6_CONTROLS_PASS adapters=2 cases=160 variants=20 scopes=2 transports=2");
    return 0;
}

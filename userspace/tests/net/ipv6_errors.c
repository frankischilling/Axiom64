// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_ERRORS"
#define IPV6_BARRIER_PROTOCOL 0x88bc
#define IPV6_BARRIER_MAGIC "IP6E"
#include "ipv6_fixture.h"
#include <linux/errqueue.h>

static void pause_errors(void) {
    struct timespec interval = {0, 100000000};
    check(!nanosleep(&interval, NULL), "real local diagnostic budget interval");
}

static int pending_events(int fd) {
    struct pollfd item = {.fd = fd, .events = POLLIN | POLLOUT | POLLERR};
    check(poll(&item, 1, 0) >= 0, "error queue poll");
    return item.revents;
}

static int local_socket(int type) {
    int fd = create(type);
    option(fd, IPPROTO_IPV6, IPV6_RECVERR, 1);
    connect_address(fd, loopback(type == SOCK_RAW ? 58 : 59999));
    return fd;
}

static int local_error(void) {
    int fd = local_socket(SOCK_DGRAM);
    unsigned char bytes[32];
    for (unsigned n = 0; n < sizeof(bytes); n++)
        bytes[n] = n * 7 + 3;
    pause_errors();
    check(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "actual unbound UDP destination");
    readable(fd, POLLERR);
    return fd;
}

static void empty_queue(int fd) {
    unsigned char byte;
    struct iovec vector = {&byte, 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    uint64_t began = now();
    errno = 0;
    check(recvmsg(fd, &message, MSG_ERRQUEUE) == -1 && errno == EAGAIN,
          "empty error queue is nonblocking on a blocking description");
    check(now() - began < 1000000000ULL, "error queue does not wait for a receive deadline");
}

static void expected_control(unsigned char bytes[64], size_t capacity, int error, int origin,
                             int type, int code, unsigned mtu,
                             const struct sockaddr_in6* offender) {
    memset(bytes, 0xa7, 64);
    if (capacity < sizeof(struct cmsghdr))
        return;
    unsigned char message[60] = {0};
    struct cmsghdr header = {.cmsg_len = capacity < 60 ? capacity : 60,
                             .cmsg_level = IPPROTO_IPV6,
                             .cmsg_type = IPV6_RECVERR};
    struct sock_extended_err extended = {
        .ee_errno = error, .ee_origin = origin, .ee_type = type, .ee_code = code, .ee_info = mtu};
    memcpy(message, &header, 16);
    memcpy(message + 16, &extended, 16);
    memcpy(message + 32, offender, 28);
    memcpy(bytes, message, capacity < 60 ? capacity : 60);
}

static void option_contract(void) {
    for (int kind = SOCK_DGRAM; kind <= SOCK_RAW; kind++) {
        int fd = create(kind), alias = dup(fd), value = 7;
        check(alias >= 0 && !get(fd, IPPROTO_IPV6, IPV6_RECVERR), "default error delivery");
        unsigned cases = 0;
        for (unsigned length = 0; length < 4; length++, cases++) {
            errno = 0;
            check(syscall(SYS_setsockopt, fd, IPPROTO_IPV6, IPV6_RECVERR, (void*)1, length) == -1 &&
                      errno == EINVAL,
                  "short RECVERR imports no option bytes");
        }
        check(!syscall(SYS_setsockopt, fd, IPPROTO_IPV6, IPV6_RECVERR, NULL, 4) &&
                  !get(fd, IPPROTO_IPV6, IPV6_RECVERR),
              "null RECVERR value clears");
        cases++;
        errno = 0;
        check(syscall(SYS_setsockopt, fd, IPPROTO_IPV6, IPV6_RECVERR, (void*)1, 4) == -1 &&
                  errno == EFAULT,
              "complete RECVERR argument fault");
        cases++;
        option(fd, IPPROTO_IPV6, IPV6_RECVERR, value);
        check(get(alias, IPPROTO_IPV6, IPV6_RECVERR) == 1,
              "aliases share normalized error delivery");
        cases++;
        socklen_t length = 0;
        check(!syscall(SYS_getsockopt, fd, IPPROTO_IPV6, IPV6_RECVERR, (void*)1, &length) &&
                  !length,
              "zero-capacity error option ignores output pointer");
        cases++;
        unsigned char byte = 0xa7;
        length = 1;
        check(!getsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &byte, &length) && byte == 1 &&
                  length == 1,
              "short error option output");
        cases++;
        length = -1;
        errno = 0;
        check(syscall(SYS_getsockopt, fd, IPPROTO_IPV6, IPV6_RECVERR, (void*)1, &length) == -1 &&
                  errno == EFAULT && length == sizeof(value),
              "unsigned error option capacity clamps before output fault");
        length = -1;
        value = 0;
        check(!getsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &value, &length) && value == 1 &&
                  length == sizeof(value),
              "unsigned error option capacity clamps for valid output");
        errno = 0;
        check(syscall(SYS_getsockopt, fd, IPPROTO_IPV6, IPV6_MTU, &value, (void*)1) == -1 &&
                  errno == EFAULT,
              "IPv6 option capacity import precedes connected-route lookup");
        errno = 0;
        check(syscall(SYS_getsockopt, fd, IPPROTO_IPV6, 0x7fff, &value, (void*)1) == -1 &&
                  errno == EFAULT,
              "IPv6 option capacity import precedes unknown option lookup");
        cases++;
        option(alias, IPPROTO_IPV6, IPV6_RECVERR, 0);
        check(!get(fd, IPPROTO_IPV6, IPV6_RECVERR), "alias clears error delivery");
        cases++;
        option(fd, IPPROTO_IPV6, IPV6_RECVERR, -3);
        check(get(alias, IPPROTO_IPV6, IPV6_RECVERR) == 1, "negative nonzero error delivery");
        cases++;
        errno = 0;
        check(syscall(SYS_setsockopt, fd, IPPROTO_IPV6, IPV6_RECVERR, &value, (socklen_t)-1) ==
                      -1 &&
                  errno == EINVAL,
              "signed error option length");
        cases++;
        check(cases == 13, "complete error option inventory");
        close(fd);
        close(alias);
    }
    puts("IPV6_ERRORS_OPTIONS_PASS cases=26");
}

static void local_receive_contract(void) {
    for (unsigned number = 0; number < 30; number++) {
        int fd = local_error();
        unsigned char bytes[64], control[128], wanted[64];
        struct sockaddr_in6 name;
        memset(bytes, 0xa7, sizeof(bytes));
        memset(control, 0xa7, sizeof(control));
        memset(&name, 0xa7, sizeof(name));
        struct iovec vector = {bytes, sizeof(bytes)};
        struct msghdr message = {.msg_name = &name,
                                 .msg_namelen = sizeof(name),
                                 .msg_iov = &vector,
                                 .msg_iovlen = 1,
                                 .msg_control = control,
                                 .msg_controllen = sizeof(control),
                                 .msg_flags = 0x13579};
        struct msghdr* target = &message;
        unsigned flags = MSG_ERRQUEUE;
        unsigned char* mapping = NULL;
        if (number == 1 || number == 2) {
            vector.iov_len = 3;
            if (number == 2)
                flags |= MSG_TRUNC;
        }
        if (number == 3)
            flags |= MSG_PEEK;
        size_t capacities[] = {0, 15, 16, 20, 59, 60, 61, 63, 64};
        if (number >= 4 && number <= 12)
            message.msg_controllen = capacities[number - 4];
        if (number == 13)
            message.msg_control = NULL;
        if (number == 14)
            message.msg_control = (void*)1;
        if (number == 15)
            vector.iov_base = (void*)1;
        if (number == 16)
            message.msg_name = (void*)1;
        if (number == 17)
            message.msg_namelen = 0;
        if (number == 18)
            message.msg_namelen = -1;
        if (number == 19) {
            message.msg_name = NULL;
            message.msg_namelen = -1;
        }
        if (number == 20)
            message.msg_iov = (void*)1;
        if (number == 21)
            target = (void*)1;
        if (number == 22 || number == 23) {
            mapping = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            check(mapping != MAP_FAILED, "owned error receive guard");
            if (number == 22) {
                memcpy(mapping, &message, sizeof(message));
                check(!mprotect(mapping, 4096, PROT_READ), "read-only message guard");
                target = (void*)mapping;
            } else {
                check(!mprotect(mapping + 4096, 4096, PROT_NONE), "control payload guard");
                message.msg_control = mapping + 4096 - 16;
                memset(message.msg_control, 0xa7, 16);
            }
        }
        if (number == 24)
            vector.iov_len = 0;
        if (number == 25) {
            message.msg_iov = (void*)1;
            message.msg_iovlen = 0;
        }
        if (number == 26)
            message.msg_controllen = UINT32_MAX;
        if (number == 27)
            flags |= MSG_CMSG_CLOEXEC;
        if (number == 28)
            flags |= MSG_WAITALL;
        if (number == 29)
            option(fd, IPPROTO_IPV6, IPV6_RECVERR, 0);
        errno = 0;
        long result = syscall(SYS_recvmsg, fd, target, flags);
        int error = result < 0 ? errno : 0;
        struct msghdr actual = number == 22 ? *(struct msghdr*)mapping : message;
        int expected_error = number == 18 ? EINVAL
                             : number == 15 || number == 16 || (number >= 20 && number <= 22)
                                 ? EFAULT
                             : number == 29 ? EAGAIN
                                            : 0;
        long wanted_result = expected_error                 ? -1
                             : number == 1 || number == 2   ? 3
                             : number == 24 || number == 25 ? 0
                                                            : 32;
        printf("IPV6_ERRORS_LOCAL case=%u result=%ld errno=%d flags=%x name=%u control=%zu\n",
               number, result, error, actual.msg_flags, actual.msg_namelen,
               (size_t)actual.msg_controllen);
        check(result == wanted_result && error == expected_error,
              "exact local error receive result");
        int retained = number == 18 || number == 20 || number == 21;
        check(pending_events(fd) == (retained || number == 29 ? POLLOUT | POLLERR : POLLOUT),
              "queued error readiness survives metadata failures");
        check(get(fd, SOL_SOCKET, SO_ERROR) == (retained || number == 29 ? ECONNREFUSED : 0),
              "error dequeue resets or preserves pending error at the native boundary");
        if (!expected_error) {
            int expected_flags = MSG_ERRQUEUE | (flags & MSG_CMSG_CLOEXEC);
            if (number == 1 || number == 2 || number == 24 || number == 25)
                expected_flags |= MSG_TRUNC;
            if ((number >= 4 && number <= 8) || number == 13)
                expected_flags |= MSG_CTRUNC;
            size_t used = number == 13 || number == 14 || number == 23 ? 0
                          : actual.msg_controllen < 16                 ? 0
                          : number >= 4 && number <= 12                ? capacities[number - 4]
                                                                       : 64;
            check(actual.msg_flags == expected_flags && actual.msg_controllen == used,
                  "native truncation flags and consumed control capacity");
            check(actual.msg_namelen == (number == 19 ? (socklen_t)-1 : sizeof(name)),
                  "native original-destination address length");
        }
        int copied = number != 15 && number != 18 && number != 20 && number != 21 && number != 29 &&
                     number != 24 && number != 25;
        check(bytes[0] == (copied ? 3 : 0xa7), "payload fault ordering and zero-length receive");
        size_t capacity = number >= 4 && number <= 12 ? capacities[number - 4] : 128;
        struct sockaddr_in6 offender = loopback(0);
        expected_control(wanted, capacity, ECONNREFUSED, SO_EE_ORIGIN_ICMP6, 1, 4, 0, &offender);
        int wrote_control = number != 13 && number != 14 && number != 15 && number != 18 &&
                            number != 20 && number != 21 && number != 23 && number != 29;
        unsigned char untouched[64];
        memset(untouched, 0xa7, sizeof(untouched));
        check(!memcmp(control, wrote_control ? wanted : untouched, 64),
              "every control byte and untouched alignment padding");
        if (number == 23)
            check(!memcmp(mapping + 4096 - 16, wanted, 16),
                  "control header remains visible after a later control fault");
        if (retained) {
            struct msghdr tail = {.msg_iov = &vector, .msg_iovlen = 1};
            vector = (struct iovec){bytes, sizeof(bytes)};
            check(recvmsg(fd, &tail, MSG_ERRQUEUE) == 32,
                  "metadata failure retains actual queued payload");
        }
        empty_queue(fd);
        if (mapping)
            check(!munmap(mapping, 8192), "release error receive guard");
        close(fd);
    }
    puts("IPV6_ERRORS_LOCAL_PASS cases=30");
}

static void local_admission(void) {
    const size_t lengths[] = {0,    1,    2,     3,     4,     1232,  1233,       1252,
                              1253, 1300, 65527, 65528, 65535, 65536, 2147483647, 2147483648ULL};
    unsigned char* bytes = malloc(65536);
    unsigned char* boundary =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(bytes && boundary != MAP_FAILED && !mprotect(boundary + 4096, 4096, PROT_NONE),
          "owned output admission data and short raw protocol prefix");
    memset(bytes, 0x4e, 65536);
    bytes[0] = boundary[4094] = 129;
    bytes[1] = boundary[4095] = 17;
    for (int kind = SOCK_DGRAM; kind <= SOCK_RAW; kind++)
        for (unsigned n = 0; n < 16; n++)
            for (unsigned pointer = 0; pointer < 3; pointer++) {
                int fd = local_socket(kind);
                option(fd, IPPROTO_IPV6, IPV6_MTU, 1280);
                option(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO);
                size_t length = lengths[n];
                int large = length + (kind == SOCK_DGRAM ? 48 : 40) > 1280;
                if (kind == SOCK_DGRAM && !large)
                    pause_errors();
                void* data = pointer == 0 ? bytes : pointer == 1 ? (void*)1 : boundary + 4094;
                errno = 0;
                long result = send(fd, data, length, MSG_DONTWAIT);
                int error = result < 0 ? errno : 0;
                int expected = kind == SOCK_RAW && (length < 2 || pointer == 1)           ? EFAULT
                               : large                                                    ? EMSGSIZE
                               : (pointer == 1 && length) || (pointer == 2 && length > 2) ? EFAULT
                               : kind == SOCK_RAW && length < 4                           ? EINVAL
                                                                                          : 0;
                printf(
                    "IPV6_ERRORS_ADMIT type=%d case=%u pointer=%u bytes=%zu result=%ld errno=%d\n",
                    kind, n, pointer, length, result, error);
                check(expected ? result == -1 && error == expected : result == (long)length,
                      "route and MTU admission precede remaining payload imports");
                unsigned char control[128] = {0}, received[64];
                struct sockaddr_in6 destination = {0};
                struct iovec vector = {received, sizeof(received)};
                struct msghdr message = {.msg_name = &destination,
                                         .msg_namelen = sizeof(destination),
                                         .msg_iov = &vector,
                                         .msg_iovlen = 1,
                                         .msg_control = control,
                                         .msg_controllen = sizeof(control)};
                errno = 0;
                long queued = recvmsg(fd, &message, MSG_ERRQUEUE);
                int has_error = expected == EMSGSIZE || (!expected && kind == SOCK_DGRAM);
                check(has_error ? queued >= 0 : queued == -1 && errno == EAGAIN,
                      "local failure produces exactly the native error-queue record");
                if (has_error) {
                    struct sock_extended_err extended;
                    memcpy(&extended, control + 16, sizeof(extended));
                    check(extended.ee_errno == (unsigned)(expected ? EMSGSIZE : ECONNREFUSED) &&
                              extended.ee_origin ==
                                  (expected ? SO_EE_ORIGIN_LOCAL : SO_EE_ORIGIN_ICMP6) &&
                              extended.ee_info == (expected ? 1280u : 0u) &&
                              destination.sin6_port == htons(kind == SOCK_RAW ? 0x8111 : 59999),
                          "native local error information and raw type/code destination");
                    if (expected)
                        check(queued == 0 && !memcmp(control + 32, (unsigned char[28]){0}, 28),
                              "local failures carry no payload or network offender");
                }
                check(!get(fd, SOL_SOCKET, SO_ERROR),
                      "admission errors leave no ordinary pending error");
                empty_queue(fd);
                close(fd);
            }
    free(bytes);
    check(!munmap(boundary, 8192), "release short protocol guard");
    puts("IPV6_ERRORS_ADMISSION_PASS cases=96");
}

static void take_local(int fd, unsigned char* bytes, size_t length) {
    struct iovec vector = {bytes, length};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
    check(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_PEEK) == (ssize_t)length &&
              message.msg_flags == (MSG_ERRQUEUE | MSG_CTRUNC),
          "real shared-description error bytes");
}

static void vector_receive_contract(void) {
    const size_t lengths[8][2] = {
        {INT64_MAX, 1},           {INT64_MAX, INT64_MAX},      {(size_t)INT64_MAX + 1, 0},
        {0x7ffff001, 0x7ffff001}, {32, (size_t)INT64_MAX + 1}, {32, INT64_MAX},
        {INT64_MAX, 0},           {(size_t)INT64_MAX + 1, 0}};
    unsigned char* bytes = malloc(64);
    check(bytes != NULL, "owned wide-vector receive bytes");
    for (unsigned number = 0; number < 8; number++) {
        int fd = local_error();
        memset(bytes, 0, 64);
        struct iovec vectors[2] = {{bytes, lengths[number][0]}, {bytes, lengths[number][1]}};
        struct msghdr message = {.msg_iov = vectors, .msg_iovlen = number < 6 ? 2 : 1};
        errno = 0;
        long result = recvmsg(fd, &message, MSG_ERRQUEUE);
        int error = result < 0 ? errno : 0, events = pending_events(fd);
        int success = number == 3 || number == 6;
        int expected = success ? 0 : number == 2 || number == 4 || number == 7 ? EINVAL : EFAULT;
        printf("IPV6_ERRORS_VECTOR case=%u result=%ld errno=%d flags=%x first=%u events=%x\n",
               number, result, error, message.msg_flags, bytes[0], events);
        check(result == (success ? 32 : -1) && error == expected &&
                  message.msg_flags == (success ? MSG_ERRQUEUE | MSG_CTRUNC : 0) &&
                  bytes[0] == (success ? 3 : 0) &&
                  events == (success ? POLLOUT : POLLOUT | POLLERR),
              "native wide-vector metadata validation and record retention");
        if (!success)
            take_local(fd, bytes, 32);
        empty_queue(fd);
        close(fd);
    }
    free(bytes);
    puts("IPV6_ERRORS_VECTORS_PASS cases=8");
}

static void lifetime_contract(void) {
    int fd = local_error(), alias = dup(fd);
    check(alias >= 0 && !close(fd), "error queue follows the shared description");
    int fresh = create(SOCK_DGRAM);
    check(!get(fresh, SOL_SOCKET, SO_ERROR), "reused descriptor has independent error state");
    empty_queue(fresh);
    unsigned char bytes[32];
    take_local(alias, bytes, 32);
    check(bytes[0] == 3 && !get(alias, SOL_SOCKET, SO_ERROR),
          "alias receives original queued payload");
    empty_queue(alias);
    close(alias);
    close(fresh);

    fd = local_error();
    check(get(fd, SOL_SOCKET, SO_ERROR) == ECONNREFUSED, "clear pending error before another send");
    memset(bytes, 0x5b, sizeof(bytes));
    pause_errors();
    check(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "second quoted local send");
    readable(fd, POLLERR);
    take_local(fd, bytes, 32);
    check(bytes[0] == 3 && get(fd, SOL_SOCKET, SO_ERROR) == ECONNREFUSED &&
              (pending_events(fd) & POLLERR),
          "dequeue rearms the next pending error");
    take_local(fd, bytes, 32);
    check(bytes[0] == 0x5b && !get(fd, SOL_SOCKET, SO_ERROR) && !(pending_events(fd) & POLLERR),
          "ordered error records drain independently of SO_ERROR");
    close(fd);

    fd = local_error();
    errno = 0;
    check(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == ECONNREFUSED,
          "ordinary receive consumes only the pending error");
    errno = 0;
    check(recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) == -1 && errno == EAGAIN &&
              (pending_events(fd) & POLLERR),
          "ordinary receive leaves the error queue intact");
    take_local(fd, bytes, 32);
    close(fd);

    fd = local_error();
    check(get(fd, SOL_SOCKET, SO_ERROR) == ECONNREFUSED, "clear pending error for normal data");
    int server = create(SOCK_DGRAM);
    bind_address(server, loopback(59999));
    struct sockaddr_in6 local;
    socklen_t size = sizeof(local);
    check(!getsockname(fd, (void*)&local, &size), "normal-data return address");
    check(sendto(server, "reply", 5, 0, (void*)&local, sizeof(local)) == 5,
          "real independent data reply");
    uint64_t deadline = now() + 5000000000ULL;
    for (;;) {
        struct pollfd item = {.fd = fd, .events = POLLIN};
        uint64_t current = now();
        check(current < deadline, "normal data arrives within the original readiness deadline");
        int remaining = (int)((deadline - current + 999999) / 1000000);
        check(poll(&item, 1, remaining) == 1 && (item.revents & POLLERR) &&
                  !(item.revents & ~(POLLIN | POLLERR)),
              "queued error remains visible while normal data arrives");
        if (item.revents & POLLIN)
            break;
        struct timespec interval = {0, 1000000};
        check(!nanosleep(&interval, NULL), "wait for normal data with a persistent queued error");
    }
    check((pending_events(fd) & (POLLIN | POLLERR)) == (POLLIN | POLLERR) &&
              recv(fd, bytes, sizeof(bytes), 0) == 5 && !memcmp(bytes, "reply", 5),
          "normal and error receive queues retain separate boundaries");
    take_local(fd, bytes, 32);
    close(server);
    close(fd);
    puts("IPV6_ERRORS_LIFETIME_PASS cases=4");
}

static unsigned short raw_checksum(unsigned lane, unsigned remote, int scoped,
                                   const unsigned char* bytes, unsigned length) {
    struct in6_addr source = address(lane, 2, 0, scoped).sin6_addr;
    struct in6_addr destination = address(lane, remote, 0, scoped).sin6_addr;
    unsigned sum = length + IPPROTO_ICMPV6;
    for (unsigned n = 0; n < 16; n += 2) {
        sum += (unsigned)source.s6_addr[n] << 8 | source.s6_addr[n + 1];
        sum += (unsigned)destination.s6_addr[n] << 8 | destination.s6_addr[n + 1];
    }
    for (unsigned n = 0; n < length; n += 2)
        sum += (unsigned)bytes[n] << 8 | (n + 1 < length ? bytes[n + 1] : 0);
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return (unsigned short)~sum;
}

static void wire(unsigned lane) {
    const unsigned types[13] = {1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 4, 4, 4};
    const unsigned codes[13] = {0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 0, 1, 2};
    const unsigned errors[13] = {ENETUNREACH, EACCES, EHOSTUNREACH, EHOSTUNREACH, ECONNREFUSED,
                                 EACCES,      EACCES, EPROTO,       EHOSTUNREACH, EHOSTUNREACH,
                                 EPROTO,      EPROTO, EPROTO};
    for (unsigned sequence = 0; sequence < 60; sequence++) {
        int pmtu = sequence < 24;
        unsigned kind = pmtu            ? sequence / 12 + 2
                        : sequence < 50 ? (sequence - 24) / 13 + 2
                                        : (sequence - 50) / 5 + 2;
        unsigned mode = pmtu ? sequence % 6 : 1, scoped = pmtu ? sequence % 12 / 6 : 0;
        int fd = create(kind);
        char device[16];
        snprintf(device, sizeof(device), "eth%u", lane);
        check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1),
              "quoted error device ownership");
        if (kind == SOCK_DGRAM)
            option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
        option(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, mode);
        option(fd, IPPROTO_IPV6, IPV6_RECVERR, 1);
        bind_address(fd, address(lane, 2, kind == SOCK_DGRAM ? 47000 + sequence : 0, scoped));
        struct sockaddr_in6 remote =
            address(lane, 16 + sequence, kind == SOCK_DGRAM ? 48000 + sequence : 58, scoped);
        connect_address(fd, remote);
        unsigned char bytes[1300], expected[1300];
        unsigned length = pmtu ? 1300 : 16;
        for (unsigned n = 0; n < length; n++)
            bytes[n] = n * 19 + sequence * 3 + lane;
        if (kind == SOCK_RAW) {
            bytes[0] = 129;
            bytes[1] = bytes[2] = bytes[3] = 0;
        }
        memcpy(expected, bytes, length);
        if (kind == SOCK_RAW) {
            unsigned short value = raw_checksum(lane, 16 + sequence, scoped, expected, length);
            expected[2] = value >> 8;
            expected[3] = value;
        }
        barrier(lane, sequence * 3 + 1);
        check(send(fd, bytes, length, 0) == (ssize_t)length, "original quoted wire datagram");
        barrier(lane, sequence * 3 + 2);
        int queued = sequence < 50 && !(pmtu && kind == SOCK_DGRAM && mode >= 4);
        unsigned error = !queued ? 0 : pmtu ? EMSGSIZE : errors[(sequence - 24) % 13];
        unsigned type = pmtu ? 2 : sequence < 50 ? types[(sequence - 24) % 13] : 1;
        unsigned code = pmtu ? 0 : sequence < 50 ? codes[(sequence - 24) % 13] : 4;
        int mtu = get(fd, IPPROTO_IPV6, IPV6_MTU);
        int observed_error = get(fd, SOL_SOCKET, SO_ERROR);
        check(mtu == (pmtu && (kind == SOCK_RAW || mode < 4) ? 1280 : 1500) &&
                  observed_error == (int)error && !!(pending_events(fd) & POLLERR) == queued,
              "queued errors remain readable after clearing SO_ERROR");
        unsigned char received[64], control[64], wanted[64];
        memset(received, 0xa7, sizeof(received));
        memset(control, 0xa7, sizeof(control));
        struct sockaddr_in6 destination;
        memset(&destination, 0xa7, sizeof(destination));
        unsigned capacity = sequence % 4 == 0 ? 0 : sequence % 4 == 1 ? 3 : 64;
        struct iovec vectors[3] = {{received, 0},
                                   {received, capacity ? 1 : 0},
                                   {received + 1, capacity ? capacity - 1 : 0}};
        struct msghdr message = {.msg_name = &destination,
                                 .msg_namelen = sizeof(destination),
                                 .msg_iov = vectors,
                                 .msg_iovlen = 3,
                                 .msg_control = control,
                                 .msg_controllen = sizeof(control)};
        errno = 0;
        long result = recvmsg(fd, &message, MSG_ERRQUEUE | (sequence % 4 == 2 ? MSG_PEEK : 0));
        unsigned quoted = pmtu ? kind == SOCK_DGRAM ? 48 : 56 : 16;
        unsigned copied = capacity < quoted ? capacity : quoted;
        if (queued) {
            struct sockaddr_in6 offender = address(lane, 250, 0, scoped);
            struct sockaddr_in6 wanted_destination = remote;
            wanted_destination.sin6_port = kind == SOCK_DGRAM ? remote.sin6_port : 0;
            expected_control(wanted, sizeof(wanted), error, SO_EE_ORIGIN_ICMP6, type, code,
                             pmtu ? 1280 : 0, &offender);
            check(result == copied &&
                      message.msg_flags == (MSG_ERRQUEUE | (copied < quoted ? MSG_TRUNC : 0)) &&
                      message.msg_controllen == 64 && message.msg_namelen == sizeof(destination) &&
                      !memcmp(&destination, &wanted_destination, sizeof(destination)) &&
                      !memcmp(control, wanted, sizeof(control)) &&
                      !memcmp(received, expected, copied),
                  "complete quoted payload, destination and extended error control");
        } else
            check(result == -1 && errno == EAGAIN, "rejected hints do not enter the error queue");
        printf("IPV6_ERRORS_WIRE lane=%u case=%u type=%u scope=%u mode=%u mtu=%d error=%d "
               "queued=%d result=%ld flags=%x name=",
               lane, sequence, kind, scoped, mode, mtu, observed_error, result >= 0, result,
               message.msg_flags);
        for (unsigned n = 0; n < sizeof(destination); n++)
            printf("%02x", ((unsigned char*)&destination)[n]);
        printf(" control=");
        for (unsigned n = 0; n < sizeof(control); n++)
            printf("%02x", control[n]);
        printf(" payload=");
        for (unsigned n = 0; n < sizeof(received); n++)
            printf("%02x", received[n]);
        puts("");
        check(!get(fd, SOL_SOCKET, SO_ERROR) && !(pending_events(fd) & POLLERR),
              "error dequeue retires the final pending error");
        empty_queue(fd);
        if (pmtu) {
            errno = 0;
            long sent = send(fd, bytes, length, 0);
            int send_error = sent < 0 ? errno : 0;
            printf("IPV6_ERRORS_SEND lane=%u case=%u result=%ld errno=%d\n", lane, sequence, sent,
                   send_error);
            check(mode == 2 ? sent == -1 && send_error == EMSGSIZE : sent == 1300,
                  "error queue preserves subsequent output policy");
            if (mode == 2) {
                message.msg_controllen = 64;
                message.msg_namelen = sizeof(destination);
                check(recvmsg(fd, &message, MSG_ERRQUEUE) == 0,
                      "local path limit reports a copied notification");
                struct sock_extended_err local;
                memcpy(&local, control + 16, sizeof(local));
                struct sockaddr_in6 local_destination = remote, no_offender = {0};
                local_destination.sin6_port = kind == SOCK_RAW ? htons(0x8100) : remote.sin6_port;
                local_destination.sin6_scope_id = 0;
                expected_control(wanted, 64, EMSGSIZE, SO_EE_ORIGIN_LOCAL, 0, 0, 1280,
                                 &no_offender);
                check(local.ee_errno == EMSGSIZE && local.ee_origin == SO_EE_ORIGIN_LOCAL &&
                          local.ee_info == 1280 && !get(fd, SOL_SOCKET, SO_ERROR) &&
                          !memcmp(&destination, &local_destination, sizeof(destination)) &&
                          !memcmp(control, wanted, sizeof(control)),
                      "native local learned-limit error metadata");
            }
        }
        barrier(lane, sequence * 3 + 3);
        close(fd);
    }
    printf("IPV6_ERRORS_WIRE_PASS lane=%u cases=60\n", lane);
}

int main(int argc, char** argv) {
    option_contract();
    local_receive_contract();
    vector_receive_contract();
    local_admission();
    lifetime_contract();
    if (argc == 2 && !strcmp(argv[1], "--local")) {
        puts("IPV6_ERRORS_LOCAL_ONLY_PASS local=30 admission=96 options=26 lifetime=4 vectors=8");
        return 0;
    }
    check(argc == 1, "selected complete error queue cohort");
    int control = fixture_interfaces();
    for (unsigned lane = 0; lane < 2; lane++)
        wire(lane);
    close(control);
    for (unsigned lane = 0; lane < 2; lane++)
        close(packets[lane]);
    puts("IPV6_ERRORS_PASS adapters=2 wire=120 local=30 admission=96 options=26 lifetime=4 "
         "vectors=8");
}

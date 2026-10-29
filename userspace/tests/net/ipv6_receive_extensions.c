// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(int value, const char* reason) {
    if (!value) {
        fprintf(stderr, "IPV6_RECEIVE_EXTENSION_LOCAL_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static void header(int fd, int kind, unsigned value) {
    unsigned char bytes[8] = {250, 0, 30, 4, value, value, value, value};
    check(!setsockopt(fd, 41, kind, bytes, sizeof(bytes)), "original sender extension");
    memset(bytes, 0xa5, sizeof(bytes));
}

static void one(unsigned raw, unsigned ordinary, unsigned variant, unsigned number) {
    int receiver = socket(10, raw ? 3 : 2, raw ? 58 : 0),
        sender = socket(10, raw ? 3 : 2, raw ? 58 : 0);
    check(receiver >= 0 && sender >= 0, "original descriptors");
    int alias = dup(receiver);
    check(alias >= 0, "receive alias");
    if (raw) {
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(129, &filter);
        check(!setsockopt(receiver, 58, 1, &filter, sizeof(filter)), "raw receive filter");
    }
    struct sockaddr_in6 local = {.sin6_family = 10, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    check(!bind(receiver, (void*)&local, sizeof(local)), "receiver loopback binding");
    socklen_t local_size = sizeof(local);
    check(!getsockname(receiver, (void*)&local, &local_size), "actual receiver address");
    header(sender, 54, 0x11);
    header(sender, 59, 0x55);
    unsigned char routing[24] = {250, 2, 4, 0, 0, 0, 0x73, 0x74};
    routing[23] = 1;
    if (variant != 1)
        check(!setsockopt(sender, 41, 57, routing, sizeof(routing)), "stored zero-left SRH");
    memset(routing, 0xa5, sizeof(routing));
    int enabled = 1;
    check(!setsockopt(receiver, 41, 53, &enabled, 4) && !setsockopt(receiver, 41, 58, &enabled, 4),
          "ordinary option selectors");
    unsigned char* guard =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(guard != MAP_FAILED, "owned receive guard");
    memset(guard, 0xa5, 8192);
    check(!mprotect(guard + 4096, 4096, PROT_NONE), "receive guard boundary");
    check(!fflush(stdout), "flush before isolated identity");
    pid_t child = fork();
    check(child >= 0, "isolated receive identity");
    if (!child) {
        if (ordinary)
            check(!setgid(65534) && !setuid(65534), "actual ordinary receive identity");
        int value = variant == 4 ? -7 : variant == 5 ? 8 : variant == 0 ? 0 : 1;
        const void* option = &value;
        socklen_t option_size = 4;
        if (variant == 6) {
            option = NULL;
            option_size = 3;
        }
        if (variant == 7)
            option = NULL;
        if (variant == 8)
            option = (void*)1;
        if (variant == 9)
            option_size = (socklen_t)-1;
        if (variant == 58)
            option_size = 8;
        if (variant == 59)
            option = guard + 4094;
        if (variant == 62)
            value = INT32_MIN;
        if (variant == 63)
            value = INT32_MAX;
        errno = 0;
        long set = syscall(SYS_setsockopt, alias, 41, 56, option, option_size);
        int set_error = set < 0 ? errno : 0;
        unsigned char scalar[8];
        memset(scalar, 0xa5, sizeof(scalar));
        socklen_t scalar_size = sizeof(scalar);
        errno = 0;
        long got = syscall(SYS_getsockopt, receiver, 41, 56, scalar, &scalar_size);
        int get_error = got < 0 ? errno : 0;
        unsigned char payload[32], returned[64], control[512], visible[512], after[64];
        for (unsigned n = 0; n < sizeof(payload); n++)
            payload[n] = n * 19 + number * 7;
        if (raw) {
            payload[0] = 129;
            payload[1] = payload[2] = payload[3] = 0;
        }
        check(sendto(sender, payload, sizeof(payload), 0, (void*)&local, sizeof(local)) == 32,
              "original loopback extension datagram");
        if (variant == 2 || variant == 3) {
            value = variant == 3;
            check(!setsockopt(alias, 41, 56, &value, 4) || set < 0,
                  "selection after actual queueing");
        }
        if (variant == 10) {
            close(receiver);
            receiver = dup(alias);
            check(receiver >= 0, "descriptor retirement with live alias");
        }
        memset(returned, 0xa5, sizeof(returned));
        memset(control, 0xa5, sizeof(control));
        memset(visible, 0xa5, sizeof(visible));
        memset(after, 0xa5, sizeof(after));
        size_t capacity = sizeof(control), visible_size = sizeof(control);
        static const unsigned capacities[] = {0,  1,  15, 16, 17, 23, 24, 31,  39, 40,
                                              41, 63, 64, 79, 80, 87, 88, 127, 128};
        if (variant >= 11 && variant <= 29)
            capacity = capacities[variant - 11];
        struct iovec vector = {returned, sizeof(returned)};
        struct msghdr message = {.msg_iov = &vector,
                                 .msg_iovlen = 1,
                                 .msg_control = control,
                                 .msg_controllen = capacity,
                                 .msg_flags = 0x5a5a};
        struct msghdr* target = &message;
        unsigned flags = MSG_DONTWAIT;
        if (variant == 30)
            flags |= MSG_PEEK;
        if (variant == 31) {
            vector.iov_len = 3;
            flags |= MSG_TRUNC;
        }
        if (variant == 32)
            vector.iov_base = (void*)1;
        if (variant == 33)
            message.msg_control = (void*)1;
        if (variant == 34)
            message.msg_control = NULL;
        if (variant >= 35 && variant <= 44) {
            static const unsigned prefixes[] = {1, 4, 8, 12, 16, 17, 20, 23, 24, 31};
            visible_size = prefixes[variant - 35];
            message.msg_control = guard + 4096 - visible_size;
        }
        if (variant == 45) {
            memcpy(guard, &message, sizeof(message));
            check(!mprotect(guard, 4096, PROT_READ), "read-only result structure");
            target = (void*)guard;
        }
        if (variant == 46) {
            message.msg_iov = (void*)1;
            message.msg_iovlen = 0;
        }
        if (variant == 47) {
            message.msg_iov = (void*)1;
            message.msg_iovlen = 1;
        }
        if (variant == 48)
            message.msg_controllen = UINT32_MAX;
        if (variant == 49)
            target = (void*)1;
        errno = 0;
        long result = syscall(SYS_recvmsg, receiver, target, flags);
        int error = result < 0 ? errno : 0;
        struct msghdr observed = variant == 45 ? *(struct msghdr*)guard : message;
        if (variant >= 35 && variant <= 44)
            memcpy(visible, message.msg_control, visible_size);
        else
            memcpy(visible, control, sizeof(visible));
        errno = 0;
        long later = recv(receiver, after, sizeof(after), MSG_DONTWAIT);
        int later_error = later < 0 ? errno : 0;
        if (variant >= 50) {
            unsigned length = variant == 50   ? 0
                              : variant == 51 ? 1
                              : variant == 52 ? 3
                              : variant == 53 ? 4
                              : variant == 54 ? (unsigned)-1
                                              : 4;
            if (variant == 60)
                length = 2;
            void* output = variant == 61   ? guard + 4094
                           : variant == 55 ? (void*)1
                           : variant == 56 ? NULL
                                           : scalar;
            void* length_pointer = variant == 57 ? (void*)1 : &length;
            if (variant >= 64) {
                unsigned prefix = variant - 64;
                check(!mprotect(guard + 4096, 4096, PROT_READ | PROT_WRITE),
                      "prepare readable length fault");
                length_pointer = guard + 4096 - prefix;
                unsigned capacity = UINT32_MAX;
                memcpy(length_pointer, &capacity, sizeof(capacity));
                check(!mprotect(guard + 4096, 4096, PROT_READ),
                      "readable length has a protected writable suffix");
            }
            memset(scalar, 0xa5, sizeof(scalar));
            errno = 0;
            got = syscall(SYS_getsockopt, alias, 41, 56, output, length_pointer);
            get_error = got < 0 ? errno : 0;
            scalar_size = length;
            if (variant >= 64)
                memcpy(&scalar_size, length_pointer, sizeof(scalar_size));
            if (variant == 61)
                memcpy(scalar, guard + 4094, 2);
        }
        printf("IPV6_RECEIVE_EXTENSION_LOCAL_CASE case=%u raw=%u ordinary=%u variant=%u uid=%u "
               "set=%ld set_errno=%d got=%ld get_errno=%d scalar_length=%u scalar=",
               number, raw, ordinary, variant, (unsigned)getuid(), set, set_error, got, get_error,
               scalar_size);
        for (unsigned n = 0; n < sizeof(scalar); n++)
            printf("%02x", scalar[n]);
        printf(" result=%ld errno=%d flags=%u length=%zu visible=%zu control=", result, error,
               observed.msg_flags, (size_t)observed.msg_controllen, visible_size);
        for (unsigned n = 0; n < sizeof(visible); n++)
            printf("%02x", visible[n]);
        printf(" payload=");
        for (unsigned n = 0; n < sizeof(returned); n++)
            printf("%02x", returned[n]);
        printf(" later=%ld later_errno=%d after=", later, later_error);
        for (unsigned n = 0; n < sizeof(after); n++)
            printf("%02x", after[n]);
        puts("");
        exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "complete isolated observation");
    close(sender);
    close(receiver);
    close(alias);
    munmap(guard, 8192);
}

int ipv6_receive_extensions_local(void) {
    unsigned number = 0;
    for (unsigned raw = 0; raw < 2; raw++)
        for (unsigned ordinary = 0; ordinary < 2; ordinary++)
            for (unsigned variant = 0; variant < 68; variant++)
                one(raw, ordinary, variant, number++);
    puts("IPV6_RECEIVE_EXTENSION_LOCAL_DONE cases=272");
    return 0;
}

#ifdef IPV6_RECEIVE_EXTENSIONS_STANDALONE
int main(void) {
    return ipv6_receive_extensions_local();
}
#endif

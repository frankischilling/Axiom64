// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static void require(int condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "SOCKET_IO_FATAL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static int datagram(void) {
    int descriptor = socket(AF_INET6, SOCK_DGRAM, 0);
    require(descriptor >= 0, "IPv6 datagram socket");
    return descriptor;
}

static void control_records(const unsigned char* controls, size_t length) {
    // Decode Linux x86-64 headers directly: libc iterators differ when
    // the final control contains only a truncated header.
    for (size_t at = 0; at + 16 <= length;) {
        struct {
            uint64_t size;
            int32_t level, type;
        } header;

        _Static_assert(sizeof(header) == 16, "Linux x86-64 control header");
        memcpy(&header, controls + at, sizeof(header));
        require(header.size >= 16 && header.size <= length - at, "bounded control header");
        int value = -1;
        if (header.size >= 16 + sizeof(value))
            memcpy(&value, controls + at + 16, sizeof(value));
        printf("%d:%d:%zu:%d,", header.level, header.type, (size_t)header.size, value);
        at += (header.size + 7) & ~(size_t)7;
    }
}

static void bind_device(int descriptor, const char* label, const void* name, socklen_t size) {
    errno = 0;
    int result = setsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, name, size);
    printf("SOCKET_IO bind case=%s size=%u result=%d errno=%d\n", label, size, result, errno);
}

static void bound_device(int descriptor, const char* label, socklen_t capacity) {
    unsigned char data[64];
    memset(data, 0xa5, sizeof(data));
    socklen_t size = capacity;
    errno = 0;
    int result = getsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, data, &size);
    printf("SOCKET_IO getbind case=%s capacity=%u result=%d errno=%d size=%u bytes=", label,
           capacity, result, errno, size);
    for (unsigned at = 0; at < 16; at++)
        printf("%02x", data[at]);
    putchar('\n');
}

static void device_cases(void) {
    int descriptor = datagram();
    char name[40] = {0};
    memcpy(name, "eth0", 4);
    for (socklen_t size = 4; size <= 40; size = size == 4    ? 5
                                                : size == 5  ? 15
                                                : size == 15 ? 16
                                                             : 40) {
        bind_device(descriptor, "eth0", name, size);
        if (size == 40)
            break;
    }
    for (socklen_t size = 0; size <= 40; size = size == 0    ? 4
                                                : size == 4  ? 15
                                                : size == 15 ? 16
                                                             : 40) {
        bound_device(descriptor, "bound", size);
        if (size == 40)
            break;
    }
    bind_device(descriptor, "missing", "absent0", 8);
    bound_device(descriptor, "after-missing", 16);
    bind_device(descriptor, "null", NULL, 40);
    bound_device(descriptor, "after-null", 16);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char* memory =
        mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED && !mprotect(memory + page, page, PROT_NONE), "guard pages");
    memcpy(memory + page - 15, name, 15);
    bind_device(descriptor, "clamped-guard", memory + page - 15, 40);
    memcpy(memory + page - 14, name, 14);
    bind_device(descriptor, "partial-guard", memory + page - 14, 40);
    bound_device(descriptor, "after-guard", 16);
    require(!munmap(memory, page * 2), "unmap guard pages");
    pid_t child = fork();
    require(child >= 0, "fork credential observer");
    if (!child) {
        require(!setuid(65534), "drop user identity");
        bind_device(descriptor, "ordinary-same", name, 40);
        bind_device(descriptor, "ordinary-clear", NULL, 0);
        int fresh = datagram();
        bind_device(fresh, "ordinary-first", name, 40);
        bound_device(fresh, "ordinary-bound", 16);
        close(fresh);
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
            "credential observer completion");
    bind_device(descriptor, "clear", NULL, 0);
    bound_device(descriptor, "unbound-empty", 0);
    bound_device(descriptor, "unbound", 16);
    close(descriptor);
}

static void hop_cases(void) {
    for (unsigned mode = 1; mode <= 3; mode++) {
        int receiver = datagram(), sender = datagram();
        struct sockaddr_in6 target = {0};
        target.sin6_family = AF_INET6;
        target.sin6_addr = in6addr_loopback;
        require(!bind(receiver, (const struct sockaddr*)&target, sizeof(target)), "loopback bind");
        socklen_t size = sizeof(target);
        require(!getsockname(receiver, (struct sockaddr*)&target, &size), "loopback destination");
        int alias = dup(receiver);
        require(alias >= 0, "shared receive description");
        for (unsigned option = 8; option <= 66; option = option == 8 ? 51 : 66) {
            int enabled = option == 8 ? !!(mode & 1) : option == 51 ? !!(mode & 2) : 1;
            errno = 0;
            int result = setsockopt(alias, IPPROTO_IPV6, option, &enabled, sizeof(enabled));
            printf("SOCKET_IO receive mode=%u option=%u value=%d result=%d errno=%d\n", mode,
                   option, enabled, result, errno);
            int observed = -1;
            size = sizeof(observed);
            errno = 0;
            result = getsockopt(receiver, IPPROTO_IPV6, option, &observed, &size);
            printf("SOCKET_IO receive-get mode=%u option=%u result=%d errno=%d size=%u value=%d\n",
                   mode, option, result, errno, size, observed);
            if (option == 66)
                break;
        }
        int hops = 77, traffic = 34;
        require(!setsockopt(sender, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)),
                "send hops");
        require(!setsockopt(sender, IPPROTO_IPV6, IPV6_TCLASS, &traffic, sizeof(traffic)),
                "send class");
        struct timeval timeout = {2, 0};
        require(!setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)),
                "receive bound");
        for (unsigned capacity = 0; capacity <= 128; capacity = capacity == 0    ? 15
                                                                : capacity == 15 ? 20
                                                                : capacity == 20 ? 24
                                                                : capacity == 24 ? 40
                                                                                 : 128) {
            require(sendto(sender, "x", 1, 0, (const struct sockaddr*)&target, sizeof(target)) == 1,
                    "loopback send");
            unsigned char controls[128];
            memset(controls, 0xa5, sizeof(controls));
            char byte = 0;
            struct iovec vector = {&byte, 1};
            struct msghdr message = {0};
            message.msg_iov = &vector;
            message.msg_iovlen = 1;
            message.msg_control = controls;
            message.msg_controllen = capacity;
            errno = 0;
            ssize_t received = recvmsg(alias, &message, 0);
            printf("SOCKET_IO control mode=%u capacity=%u result=%ld errno=%d flags=%d used=%zu "
                   "records=",
                   mode, capacity, (long)received, errno, message.msg_flags,
                   (size_t)message.msg_controllen);
            control_records(controls, message.msg_controllen);
            putchar('\n');
            require(received == 1 && byte == 'x', "loopback payload");
            if (capacity == 128)
                break;
        }
        close(alias);
        close(receiver);
        close(sender);
    }
}

static void error_cases(void) {
    for (unsigned mode = 1; mode <= 3; mode++) {
        int reserve = datagram();
        struct sockaddr_in6 target = {0};
        target.sin6_family = AF_INET6;
        target.sin6_addr = in6addr_loopback;
        require(!bind(reserve, (const struct sockaddr*)&target, sizeof(target)),
                "closed port reserve");
        socklen_t size = sizeof(target);
        require(!getsockname(reserve, (struct sockaddr*)&target, &size), "closed destination");
        close(reserve);
        int sender = datagram(), enabled = 1;
        require(!setsockopt(sender, IPPROTO_IPV6, IPV6_RECVERR, &enabled, sizeof(enabled)),
                "receive errors");
        enabled = !!(mode & 1);
        require(!setsockopt(sender, IPPROTO_IPV6, 8, &enabled, sizeof(enabled)),
                "legacy error hops");
        enabled = !!(mode & 2);
        require(!setsockopt(sender, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &enabled, sizeof(enabled)),
                "modern error hops");
        require(sendto(sender, "x", 1, 0, (const struct sockaddr*)&target, sizeof(target)) == 1,
                "closed port send");
        unsigned char controls[128];
        memset(controls, 0xa5, sizeof(controls));
        char byte = 0;
        struct iovec vector = {&byte, 1};
        struct msghdr message = {0};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = controls;
        message.msg_controllen = sizeof(controls);
        errno = 0;
        ssize_t received = recvmsg(sender, &message, MSG_ERRQUEUE);
        printf("SOCKET_IO error mode=%u result=%ld errno=%d flags=%d used=%zu records=", mode,
               (long)received, errno, message.msg_flags, (size_t)message.msg_controllen);
        control_records(controls, message.msg_controllen);
        putchar('\n');
        require(received == 1 && byte == 'x', "error queue payload");
        close(sender);
    }
}

int ipv6_socket_configuration(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    device_cases();
    hop_cases();
    error_cases();
    puts("SOCKET_IO_COMPLETE");
    return 0;
}

#ifndef IPV6_SOCKET_CONFIGURATION_INTEGRATED
int main(void) {
    return ipv6_socket_configuration();
}
#endif

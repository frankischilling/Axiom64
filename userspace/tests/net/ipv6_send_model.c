// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

static void check(int value, const char* what) {
    if (!value) {
        fprintf(stderr, "IPV6_SEND_MODEL_FAIL %s errno=%d\n", what, errno);
        exit(1);
    }
}

static int guarded_send(int sender, struct sockaddr_in6* target, void* guard, unsigned size) {
    unsigned char sent = 0x5a;
    struct iovec vector = {&sent, 1};
    struct msghdr message = {.msg_name = target,
                             .msg_namelen = sizeof(*target),
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = guard,
                             .msg_controllen = size};
    errno = 0;
    ssize_t result = sendmsg(sender, &message, MSG_DONTWAIT);
    int error = errno;
    check(result == -1 && (error == EFAULT || error == ENOBUFS),
          "actual protected import or option-memory rejection");
    return error;
}

int main(void) {
    struct utsname kernel;
    check(!uname(&kernel), "actual kernel");
    printf("IPV6_SEND_MODEL_KERNEL release=%s\n", kernel.release);
    int receiver = socket(AF_INET6, SOCK_DGRAM, 0), sender = socket(AF_INET6, SOCK_DGRAM, 0);
    check(receiver >= 0 && sender >= 0, "owned descriptions");
    struct sockaddr_in6 target = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    check(!bind(receiver, (struct sockaddr*)&target, sizeof(target)), "owned target");
    socklen_t length = sizeof(target);
    check(!getsockname(receiver, (struct sockaddr*)&target, &length) && length == sizeof(target),
          "actual target");
    int enabled = 1, sticky = 18;
    check(!setsockopt(receiver, IPPROTO_IPV6, IPV6_RECVTCLASS, &enabled, 4) &&
              !setsockopt(sender, IPPROTO_IPV6, IPV6_TCLASS, &sticky, 4),
          "explicit receiver and shared output class");
    for (unsigned at = 0; at < 2; at++) {
        unsigned char control[CMSG_SPACE(4)] = {0}, incoming[CMSG_SPACE(4)], sent = 0x5a,
                      received = 0xa5;
        int value = at ? -1 : 170;
        struct cmsghdr header = {
            .cmsg_len = CMSG_LEN(4), .cmsg_level = IPPROTO_IPV6, .cmsg_type = IPV6_TCLASS};
        memcpy(control, &header, sizeof(header));
        memcpy(control + sizeof(header), &value, 4);
        struct iovec vector = {&sent, 1};
        struct msghdr message = {.msg_name = &target,
                                 .msg_namelen = sizeof(target),
                                 .msg_iov = &vector,
                                 .msg_iovlen = 1,
                                 .msg_control = control,
                                 .msg_controllen = sizeof(control)};
        check(sendmsg(sender, &message, 0) == 1, "actual controlled datagram");
        memset(incoming, 0xa5, sizeof(incoming));
        vector.iov_base = &received;
        struct msghdr output = {.msg_iov = &vector,
                                .msg_iovlen = 1,
                                .msg_control = incoming,
                                .msg_controllen = sizeof(incoming)};
        check(recvmsg(receiver, &output, MSG_DONTWAIT) == 1 && received == sent &&
                  output.msg_controllen == sizeof(incoming) && !output.msg_flags,
              "actual received datagram and complete class control");
        memcpy(&header, incoming, sizeof(header));
        int observed;
        memcpy(&observed, incoming + sizeof(header), 4);
        check(header.cmsg_len == CMSG_LEN(4) && header.cmsg_level == IPPROTO_IPV6 &&
                  header.cmsg_type == IPV6_TCLASS,
              "original class control identity");
        length = 4;
        check(!getsockopt(sender, IPPROTO_IPV6, IPV6_TCLASS, &sticky, &length) && sticky == 18 &&
                  length == 4,
              "per-message override preserves the shared option");
        printf("IPV6_SEND_MODEL_CASE case=%u input=%d class=%d byte=%u sticky=%d control=", at,
               value, observed, received, sticky);
        for (unsigned n = 0; n < sizeof(incoming); n++)
            printf("%02x", incoming[n]);
        puts("");
    }
    void* guard = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(guard != MAP_FAILED, "owned protected control input");
    unsigned low = 1, limit = 2147483647;
    check(guarded_send(sender, &target, guard, low) == EFAULT &&
              guarded_send(sender, &target, guard, limit) == ENOBUFS,
          "bounded actual option-memory transition");
    while (limit - low > 1) {
        unsigned middle = low + (limit - low) / 2;
        if (guarded_send(sender, &target, guard, middle) == ENOBUFS)
            limit = middle;
        else
            low = middle;
    }
    printf("IPV6_SEND_MODEL_OPTMEM max=%u\n", limit);
    unsigned sizes[] = {1, limit - 1, limit, 65535, 65536, 131071, 131072, 2147483647};
    for (unsigned at = 0; at < sizeof(sizes) / sizeof(sizes[0]); at++) {
        int error = guarded_send(sender, &target, guard, sizes[at]);
        check(error == (sizes[at] >= limit ? ENOBUFS : EFAULT),
              "actual option allocation boundary precedes protected byte import");
        printf("IPV6_SEND_MODEL_GUARD case=%u size=%u result=-1 errno=%d\n", at, sizes[at], error);
    }
    check(!munmap(guard, 4096) && !close(sender) && !close(receiver), "retire owned inputs");
    puts("IPV6_SEND_MODEL_DONE cases=2 guards=8");
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static void check(int ok, const char* label) {
    if (!ok) {
        printf("IPV6_EXTENSION_LOCAL_FAIL %s errno=%d\n", label, errno);
        exit(90);
    }
}

static void extension(unsigned char* bytes, size_t* used, int type, unsigned size, unsigned hdrlen,
                      unsigned value) {
    check(*used + CMSG_SPACE(size) <= 8192, "bounded extension input");
    struct cmsghdr header = {.cmsg_len = CMSG_LEN(size), .cmsg_level = 41, .cmsg_type = type};
    memcpy(bytes + *used, &header, sizeof(header));
    unsigned char* data = bytes + *used + sizeof(header);
    memset(data, 0, size);
    if (size)
        data[0] = 250;
    if (size > 1)
        data[1] = hdrlen;
    if (size >= 8) {
        data[2] = 0x1e;
        data[3] = 4;
        memset(data + 4, value, 4);
    }
    if (type == 57 && size >= 8) {
        memset(data + 2, 0, size - 2);
        if (size == 24) {
            data[2] = 2;
            data[3] = 1;
            data[23] = 1;
        }
    }
    *used += CMSG_SPACE(size);
}

static void one(unsigned raw, unsigned named, unsigned drop, unsigned variant, unsigned number) {
    int receiver = socket(AF_INET6, raw ? SOCK_RAW : SOCK_DGRAM, raw ? 58 : 0);
    int sender = socket(AF_INET6, raw ? SOCK_RAW : SOCK_DGRAM, raw ? 58 : 0);
    check(receiver >= 0 && sender >= 0, "socket pair");
    if (raw) {
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(129, &filter);
        check(!setsockopt(receiver, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)),
              "raw filter");
    }
    int enabled = 1;
    errno = 0;
    int hop_option = setsockopt(receiver, 41, 53, &enabled, 4);
    int hop_error = hop_option < 0 ? errno : 0;
    errno = 0;
    int destination_option = setsockopt(receiver, 41, 58, &enabled, 4);
    int destination_error = destination_option < 0 ? errno : 0;
    struct sockaddr_in6 local = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    check(!bind(receiver, (struct sockaddr*)&local, sizeof(local)), "receiver bind");
    socklen_t local_length = sizeof(local);
    check(!getsockname(receiver, (struct sockaddr*)&local, &local_length), "receiver identity");
    if (!named)
        check(!connect(sender, (struct sockaddr*)&local, sizeof(local)), "connected destination");
    unsigned char control[8192], original[8192], payload[32], receive[64], returned[8192];
    memset(control, 0xa5, sizeof(control));
    size_t used = 0;
    switch (variant) {
    case 0:
    case 31:
        break;
    case 1:
    case 28:
        extension(control, &used, 54, 8, 0, 0x11);
        break;
    case 2:
    case 30:
        extension(control, &used, 59, 8, 0, 0x22);
        break;
    case 3:
        extension(control, &used, 55, 8, 0, 0x33);
        break;
    case 4:
        extension(control, &used, 54, 8, 0, 0x11);
        extension(control, &used, 59, 8, 0, 0x22);
        break;
    case 5:
        extension(control, &used, 59, 8, 0, 0x22);
        extension(control, &used, 54, 8, 0, 0x11);
        break;
    case 6:
        extension(control, &used, 54, 8, 0, 0x11);
        extension(control, &used, 54, 8, 0, 0x22);
        break;
    case 7:
        extension(control, &used, 59, 8, 0, 0x11);
        extension(control, &used, 59, 8, 0, 0x22);
        break;
    case 8:
        extension(control, &used, 3, 8, 0, 0x11);
        break;
    case 9:
        extension(control, &used, 4, 8, 0, 0x22);
        break;
    case 10:
        extension(control, &used, 3, 8, 0, 0x11);
        extension(control, &used, 4, 8, 0, 0x22);
        break;
    case 11:
        extension(control, &used, 54, 8, 0, 0x11);
        extension(control, &used, 3, 8, 0, 0x22);
        break;
    case 12:
        extension(control, &used, 59, 8, 0, 0x11);
        extension(control, &used, 4, 8, 0, 0x22);
        break;
    case 13:
        extension(control, &used, 54, 2, 0, 0);
        break;
    case 14:
        extension(control, &used, 54, 7, 0, 0);
        break;
    case 15:
    case 29:
        extension(control, &used, 54, 8, 1, 0);
        break;
    case 16:
        extension(control, &used, 54, 16, 0, 0x11);
        break;
    case 17:
        extension(control, &used, 54, 8, 0, 0x11);
        control[16] = 0;
        break;
    case 18:
        extension(control, &used, 54, 2048, 255, 0x11);
        break;
    case 19:
        extension(control, &used, 59, 2048, 255, 0x22);
        break;
    case 20:
        extension(control, &used, 4, 8, 0, 0x11);
        extension(control, &used, 4, 8, 0, 0x22);
        break;
    case 21:
        extension(control, &used, 4, 8, 0, 0x11);
        extension(control, &used, 59, 8, 0, 0x22);
        break;
    case 22:
        extension(control, &used, 55, 8, 0, 0x11);
        extension(control, &used, 59, 8, 0, 0x22);
        break;
    case 23:
        extension(control, &used, 55, 8, 0, 0x11);
        extension(control, &used, 55, 8, 0, 0x22);
        break;
    case 24:
        extension(control, &used, 57, 8, 0, 0);
        break;
    case 25:
        extension(control, &used, 57, 24, 2, 0);
        break;
    case 26:
        extension(control, &used, 60, 8, 0, 0x11);
        break;
    case 27:
        extension(control, &used, 54, 0, 0, 0);
        break;
    }
    memcpy(original, control, sizeof(control));
    memset(payload, 0x7b, sizeof(payload));
    if (raw) {
        payload[0] = 129;
        payload[1] = payload[2] = payload[3] = 0;
    }
    struct iovec vector = {payload, sizeof(payload)};
    struct msghdr message = {.msg_name = named ? &local : NULL,
                             .msg_namelen = named ? sizeof(local) : 0,
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control,
                             .msg_controllen = used};
    fflush(stdout);
    pid_t child = fork();
    check(child >= 0, "probe child");
    if (!child) {
        if (drop)
            check(!setuid(65534), "actual ordinary user");
        errno = 0;
        long result = syscall(SYS_sendmsg, sender, &message, MSG_DONTWAIT);
        int error = result < 0 ? errno : 0;
        struct pollfd item = {.fd = receiver, .events = POLLIN};
        check(poll(&item, 1, 20) >= 0, "bounded observation");
        memset(returned, 0xa5, sizeof(returned));
        memset(receive, 0xa5, sizeof(receive));
        struct iovec output = {receive, sizeof(receive)};
        struct msghdr incoming = {.msg_iov = &output,
                                  .msg_iovlen = 1,
                                  .msg_control = returned,
                                  .msg_controllen = sizeof(returned)};
        errno = 0;
        long received = recvmsg(receiver, &incoming, MSG_DONTWAIT);
        int receive_error = received < 0 ? errno : 0;
        printf("IPV6_EXTENSION_LOCAL_CASE case=%u raw=%u named=%u drop=%u variant=%u uid=%u "
               "hop_errno=%d destination_errno=%d result=%ld errno=%d received=%ld "
               "receive_errno=%d flags=%d length=%zu unchanged=%u control=",
               number, raw, named, drop, variant, (unsigned)getuid(), hop_error, destination_error,
               result, error, received, receive_error, incoming.msg_flags,
               (size_t)incoming.msg_controllen, !memcmp(original, control, sizeof(control)));
        if (received >= 0)
            for (size_t n = 0; n < incoming.msg_controllen; n++)
                printf("%02x", returned[n]);
        printf(" payload=");
        for (unsigned n = 0; n < sizeof(receive); n++)
            printf("%02x", receive[n]);
        puts("");
        fflush(stdout);
        _exit(0);
    }
    int status = 0;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "completed probe child");
    check(!close(sender) && !close(receiver), "retire probe descriptions");
}

int ipv6_extension_controls_local(void) {
    struct utsname identity;
    check(!uname(&identity), "actual kernel");
    printf("IPV6_EXTENSION_LOCAL_KERNEL system=%s release=%s\n", identity.sysname,
           identity.release);
    unsigned cases = 0;
    for (unsigned raw = 0; raw < 2; raw++)
        for (unsigned named = 0; named < 2; named++)
            for (unsigned drop = 0; drop < 2; drop++)
                for (unsigned variant = 0; variant < 32; variant++)
                    one(raw, named, drop, variant, cases++);
    printf("IPV6_EXTENSION_LOCAL_DONE cases=%u\n", cases);
    return 0;
}

#ifndef IPV6_SEND_CONTROLS_INTEGRATED
int main(void) {
    return ipv6_extension_controls_local();
}
#endif

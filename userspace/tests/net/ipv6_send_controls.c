// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static unsigned cases, loopback;

static void check(int ok, const char* what) {
    if (!ok) {
        printf("IPV6_SEND_CONTROLS_FAIL case=%u %s errno=%d\n", cases, what, errno);
        exit(1);
    }
}

static void bytes(const void* pointer, size_t count) {
    const unsigned char* data = pointer;
    for (size_t at = 0; at < count; at++)
        printf("%02x", data[at]);
}

static void append(unsigned char* control, size_t* length, int level, int type, const void* data,
                   size_t size) {
    struct cmsghdr header = {.cmsg_len = CMSG_LEN(size), .cmsg_level = level, .cmsg_type = type};
    memcpy(control + *length, &header, sizeof(header));
    if (size)
        memcpy(control + *length + sizeof(header), data, size);
    *length += CMSG_SPACE(size);
}

static int get(int fd, int option) {
    int value = -999;
    socklen_t size = 4;
    errno = 0;
    int result = getsockopt(fd, IPPROTO_IPV6, option, &value, &size);
    return result ? -errno : value;
}

static void one(unsigned raw, unsigned named, unsigned variant) {
    int receiver = socket(AF_INET6, raw ? SOCK_RAW : SOCK_DGRAM, raw ? 58 : 0);
    int sender = socket(AF_INET6, raw ? SOCK_RAW : SOCK_DGRAM, raw ? 58 : 0);
    check(receiver >= 0 && sender >= 0, "descriptions");
    int alias = dup(sender), enabled = 1, hops = 33, traffic = 0x12;
    check(alias >= 0 && !setsockopt(sender, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, 4),
          "shared hop option");
    // Keep recording the pre-feature kernel even when its sticky class is absent.
    errno = 0;
    int sticky = setsockopt(sender, IPPROTO_IPV6, IPV6_TCLASS, &traffic, 4);
    int sticky_error = sticky < 0 ? errno : 0;
    for (unsigned n = 0; n < 3; n++) {
        int option = (int[]){IPV6_RECVPKTINFO, IPV6_RECVHOPLIMIT, IPV6_RECVTCLASS}[n];
        check(!setsockopt(receiver, IPPROTO_IPV6, option, &enabled, 4), "actual receive controls");
    }
    if (raw) {
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(129, &filter);
        check(!setsockopt(receiver, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)),
              "owned raw input");
    }
    struct sockaddr_in6 local = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    local.sin6_port = htons(raw ? 0 : 55100);
    check(!bind(receiver, (struct sockaddr*)&local, 28), "receiver bind");
    struct sockaddr_in6 source = local;
    source.sin6_port = htons(raw ? 0 : 55101);
    check(!bind(sender, (struct sockaddr*)&source, 28), "sender bind");
    if (!named)
        check(!connect(sender, (struct sockaddr*)&local, 28), "connected destination");
    if (variant == 51)
        check(!setsockopt(sender, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3), "bound output device");
    unsigned char payload[32], received[32], incoming[192], control[256], original[256];
    for (unsigned at = 0; at < 32; at++)
        payload[at] = at * 19 + 7;
    if (raw) {
        payload[0] = 129;
        payload[1] = payload[2] = payload[3] = 0;
        payload[4] = 0x6d;
        payload[5] = 0x53;
        payload[6] = 0;
        payload[7] = 1;
    }
    memset(received, 0xa5, sizeof(received));
    memset(incoming, 0xa5, sizeof(incoming));
    memset(control, 0xa5, sizeof(control));
    struct in6_pktinfo info = {.ipi6_addr = IN6ADDR_LOOPBACK_INIT, .ipi6_ifindex = loopback};
    size_t length = 0;
    int value = 43;
    if (variant == 2 || variant == 9 || variant == 14 || variant == 29 || variant == 30)
        value = 0xab;
    if (variant == 5 || variant == 8)
        value = -1;
    if (variant == 6)
        value = 0;
    if (variant == 7 || variant == 9)
        value = 255;
    if (variant == 27 || variant == 29)
        value = -2;
    if (variant == 28 || variant == 30)
        value = 256;
    int type = variant == 2 || variant == 8 || variant == 9 || variant == 14 || variant == 29 ||
                       variant == 30
                   ? IPV6_TCLASS
                   : IPV6_HOPLIMIT;
    if (variant == 31 || variant == 32 || variant == 33 || variant == 34) {
        type = IPV6_DONTFRAG;
        value = variant - 31;
    }
    if (variant == 33)
        value = -1;
    if (variant == 35)
        type = 8;
    if (variant != 0)
        append(control, &length, IPPROTO_IPV6, type, &value, 4);
    if (variant == 3 || (variant >= 10 && variant <= 12) || variant == 25 || variant == 26 ||
        variant == 36 || variant == 51) {
        length = 0;
        if (variant == 10 || variant == 11)
            memset(&info.ipi6_addr, 0, 16);
        if (variant == 10 || variant == 12)
            info.ipi6_ifindex = 0;
        if (variant == 25 || variant == 51)
            info.ipi6_ifindex = 0x7ffffffe;
        if (variant == 26)
            info.ipi6_addr.s6_addr[15] = 2;
        append(control, &length, IPPROTO_IPV6, variant == 36 ? 2 : IPV6_PKTINFO, &info, 20);
    }
    if (variant == 4 || variant >= 52) {
        length = 0;
        append(control, &length, IPPROTO_IPV6, IPV6_PKTINFO, &info, 20);
        append(control, &length, IPPROTO_IPV6, IPV6_HOPLIMIT, &value, 4);
        value = 0xab;
        append(control, &length, IPPROTO_IPV6, IPV6_TCLASS, &value, 4);
    }
    if (variant == 13 || variant == 14) {
        value = variant == 13 ? 44 : 0xfe;
        append(control, &length, IPPROTO_IPV6, type, &value, 4);
    }
    if (variant == 15) {
        ((struct cmsghdr*)control)->cmsg_level = 12345;
        ((struct cmsghdr*)control)->cmsg_type = 999;
    }
    if (variant == 16 || variant == 17) {
        ((struct cmsghdr*)control)->cmsg_level = variant == 16 ? IPPROTO_IPV6 : SOL_SOCKET;
        ((struct cmsghdr*)control)->cmsg_type = 999;
    }
    if (variant == 18)
        length = 1;
    if (variant == 19)
        ((struct cmsghdr*)control)->cmsg_len = 0;
    if (variant == 20)
        ((struct cmsghdr*)control)->cmsg_len = 15;
    if (variant == 21)
        ((struct cmsghdr*)control)->cmsg_len = 16;
    if (variant == 22)
        length = 19;
    if (variant == 23)
        length = 20;
    if (variant == 24)
        ((struct cmsghdr*)control)->cmsg_len = 21;
    if (variant == 37) {
        length = 0;
        unsigned char extended[24] = {0};
        memcpy(extended, &info, 20);
        append(control, &length, IPPROTO_IPV6, IPV6_PKTINFO, extended, 24);
    }
    if (variant == 38) {
        length = 0;
        append(control, &length, IPPROTO_IPV6, IPV6_PKTINFO, &info, 19);
    }
    if (variant == 39) {
        length = 15;
    }
    if (variant == 40) {
        length = 16;
        ((struct cmsghdr*)control)->cmsg_level = 12345;
        ((struct cmsghdr*)control)->cmsg_len = 16;
    }
    if (variant == 41) {
        length = 25;
        control[24] = 0;
    }
    if (variant == 42) {
        length = 40;
        memset(control + 24, 0, 16);
    }
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED, "owned input guard");
    struct iovec vector = {.iov_base = payload, .iov_len = 32};
    struct msghdr message = {.msg_name = named ? &local : NULL,
                             .msg_namelen = named ? 28 : 0,
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control,
                             .msg_controllen = length};
    if (variant == 43 || variant == 44 || variant == 45) {
        message.msg_control = variant == 45 ? NULL : pages + 4096;
        message.msg_controllen = variant == 43 ? 0 : 1;
    }
    if (variant == 46)
        message.msg_controllen = 0x80000000ull;
    if (variant == 47 || variant == 48) {
        message.msg_iov = (struct iovec*)(pages + 4096);
        if (variant == 48)
            ((struct cmsghdr*)control)->cmsg_len = 0;
    }
    if (variant == 49 || variant == 50) {
        message.msg_name = pages + 4096;
        message.msg_namelen = 28;
        if (variant == 50)
            ((struct cmsghdr*)control)->cmsg_len = 0;
    }
    if (variant >= 52 && variant < 72) {
        unsigned prefixes[] = {0,  1,  7,  8,  9,  15, 16, 17, 19, 20,
                               23, 24, 35, 36, 39, 40, 63, 64, 87, 88};
        message.msg_control = pages + 4096 - prefixes[variant - 52];
        memcpy(message.msg_control, control, length);
    }
    if (variant >= 72 && variant < 80) {
        ((struct cmsghdr*)control)->cmsg_len = variant % 2 ? 0 : 36;
        vector.iov_base = pages + 4096;
        if (variant >= 74)
            vector.iov_len = 0;
        if (variant >= 76)
            message.msg_iovlen = 1025;
        if (variant >= 78) {
            message.msg_name = &local;
            message.msg_namelen = 28;
            local.sin6_family = 999;
        }
    }
    if (variant >= 80) {
        if (variant <= 95) {
            uint64_t sizes[] = {0,      1,      15,         16,           20,     88,
                                4096,   8192,   65535,      65536,        131071, 131072,
                                131073, 262144, 2147483647, 2147483648ull};
            message.msg_control = pages + 4096;
            message.msg_controllen = sizes[variant - 80];
        } else if (variant == 96 || variant == 97) {
            local.sin6_family = 999;
            message.msg_name = &local;
            message.msg_namelen = 28;
            if (variant == 96)
                message.msg_control = pages + 4096;
            else
                ((struct cmsghdr*)control)->cmsg_len = 0;
        } else if (variant == 98 || variant == 99 || variant == 100) {
            message.msg_controllen = 0x80000000ull;
            if (variant == 98)
                message.msg_iov = (struct iovec*)(pages + 4096);
            if (variant == 99)
                message.msg_iovlen = 1025;
            if (variant == 100) {
                message.msg_name = pages + 4096;
                message.msg_namelen = 28;
            }
        } else if (variant == 101 || variant == 102) {
            message.msg_control = NULL;
            message.msg_controllen = variant == 101 ? 0 : 20;
        } else if (variant == 103 || variant == 104) {
            vector.iov_len = 1;
            if (variant == 103)
                ((struct cmsghdr*)control)->cmsg_len = 0;
        } else if (variant == 105) {
            length = 0;
            value = 43;
            append(control, &length, IPPROTO_IPV6, IPV6_HOPLIMIT, &value, 4);
            value = -1;
            append(control, &length, IPPROTO_IPV6, IPV6_HOPLIMIT, &value, 4);
            message.msg_controllen = length;
        } else if (variant == 106 || variant == 107 || variant == 108 || variant == 109) {
            length = 0;
            if (variant <= 107) {
                append(control, &length, IPPROTO_IPV6, IPV6_PKTINFO, &info, 20);
                memset(&info, 0, sizeof(info));
                if (variant == 107)
                    info.ipi6_ifindex = 0x7ffffffe;
            } else {
                info.ipi6_ifindex = 0;
                check(inet_pton(AF_INET6, variant == 108 ? "fe80::1" : "::ffff:127.0.0.1",
                                &info.ipi6_addr) == 1,
                      "actual source override");
            }
            append(control, &length, IPPROTO_IPV6, IPV6_PKTINFO, &info, 20);
            message.msg_controllen = length;
        } else if (variant == 110 || variant == 111) {
            length = 0;
            append(control, &length, SOL_SOCKET, variant == 110 ? 1 : 2, &value,
                   variant == 110 ? 0 : 4);
            message.msg_controllen = length;
        } else if (variant >= 112 && variant <= 115) {
            length = 0;
            uint64_t wide = 43;
            append(control, &length, IPPROTO_IPV6,
                   variant == 112   ? IPV6_HOPLIMIT
                   : variant == 113 ? IPV6_TCLASS
                   : variant == 114 ? IPV6_DONTFRAG
                                    : 8,
                   &wide, variant == 115 ? 4 : 8);
            message.msg_controllen = length;
        } else if (variant == 116 || variant == 117) {
            ((struct cmsghdr*)control)->cmsg_level = 12345;
            ((struct cmsghdr*)control)->cmsg_len = variant == 116 ? 0 : UINT64_MAX;
        } else if (variant == 118) {
            local.sin6_family = 999;
            message.msg_name = &local;
            message.msg_namelen = 28;
            vector.iov_base = pages + 4096;
            message.msg_controllen = 0;
        } else if (variant == 119) {
            message.msg_iovlen = 1025;
            message.msg_control = NULL;
            message.msg_controllen = 1;
        }
    }
    memcpy(original, control, sizeof(control));
    unsigned char original_payload[32];
    memcpy(original_payload, payload, sizeof(payload));
    struct iovec original_vector = vector;
    struct msghdr before = message;
    check(!mprotect(pages + 4096, 4096, PROT_NONE), "protected input bytes");
    errno = 0;
    long result = syscall(SYS_sendmsg, alias, &message, MSG_DONTWAIT);
    int error = result < 0 ? errno : 0;
    check(!memcmp(&before, &message, sizeof(message)) &&
              !memcmp(&original_vector, &vector, sizeof(vector)) &&
              !memcmp(original_payload, payload, sizeof(payload)) &&
              !memcmp(original, control, sizeof(control)),
          "send input header, vectors, data and controls remain unchanged");
    if (variant >= 52 && variant < 72) {
        unsigned visible[] = {0,  1,  7,  8,  9,  15, 16, 17, 19, 20,
                              23, 24, 35, 36, 39, 40, 63, 64, 87, 88};
        check(!memcmp(message.msg_control, original, visible[variant - 52]),
              "protected input prefix remains unchanged");
    }
    struct iovec input = {.iov_base = received, .iov_len = 32};
    struct msghdr output = {
        .msg_iov = &input, .msg_iovlen = 1, .msg_control = incoming, .msg_controllen = 192};
    if (result >= 0) {
        struct pollfd ready = {.fd = receiver, .events = POLLIN};
        check(poll(&ready, 1, 1000) == 1, "actual loopback input");
    }
    errno = 0;
    long got = recvmsg(receiver, &output, MSG_DONTWAIT);
    int got_error = got < 0 ? errno : 0;
    printf("IPV6_SEND_CONTROLS case=%u raw=%u named=%u variant=%u sticky=%d sticky_errno=%d "
           "result=%ld errno=%d received=%ld receive_errno=%d length=%zu flags=%u hops=%d class=%d "
           "control=",
           cases++, raw, named, variant, sticky, sticky_error, result, error, got, got_error,
           (size_t)output.msg_controllen, (unsigned)output.msg_flags, get(alias, IPV6_UNICAST_HOPS),
           get(alias, IPV6_TCLASS));
    bytes(incoming, 192);
    printf(" payload=");
    bytes(received, 32);
    puts("");
    check(!munmap(pages, 8192) && !close(alias) && !close(sender) && !close(receiver),
          "release case ownership");
}

#ifdef IPV6_SEND_CONTROLS_INTEGRATED
int ipv6_send_controls_local(void) {
#else
int main(void) {
#endif
    loopback = if_nametoindex("lo");
    check(loopback > 0, "actual loopback identity");
    printf("IPV6_SEND_CONTROLS_INTERFACE loopback=%u\n", loopback);
    for (unsigned raw = 0; raw < 2; raw++)
        for (unsigned named = 0; named < 2; named++)
            for (unsigned variant = 0; variant < 120; variant++)
                one(raw, named, variant);
    puts("IPV6_SEND_CONTROLS_DONE cases=480 transports=2 destinations=2 variants=120");
    return 0;
}

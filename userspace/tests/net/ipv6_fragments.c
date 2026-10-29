// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static unsigned indices[2];
static unsigned char macs[2][6], received[65536];
static int packets[2], udp[2], scoped[2], raw[2];
static unsigned acknowledged[2];

static void check(int value, const char* reason) {
    if (!value) {
        fprintf(stderr, "IPV6_FRAGMENTS_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static uint64_t now(void) {
    struct timespec value;
    check(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic fragment clock");
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

static struct sockaddr_in6 address(unsigned lane, unsigned host, unsigned port, int link) {
    struct sockaddr_in6 result = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    if (link) {
        result.sin6_addr.s6_addr[0] = 0xfe;
        result.sin6_addr.s6_addr[1] = 0x80;
        result.sin6_scope_id = indices[lane];
    } else {
        const unsigned char prefix[6] = {0x20, 1, 0x0d, 0xb8, 0, lane + 1};
        memcpy(result.sin6_addr.s6_addr, prefix, sizeof(prefix));
    }
    result.sin6_addr.s6_addr[15] = host;
    return result;
}

static void request(unsigned lane, unsigned phase) {
    unsigned char frame[60] = {2, 'I', 'P', '6', lane, 0};
    memcpy(frame + 6, macs[lane], 6);
    frame[12] = 0x88;
    frame[13] = 0xb7;
    memcpy(frame + 14, "IP6F", 4);
    frame[18] = lane;
    frame[19] = phase;
    struct sockaddr_ll target = {.sll_family = AF_PACKET,
                                 .sll_protocol = htons(0x88b7),
                                 .sll_ifindex = indices[lane],
                                 .sll_halen = 6};
    memcpy(target.sll_addr, frame, 6);
    check(sendto(packets[lane], frame, sizeof(frame), 0, (struct sockaddr*)&target,
                 sizeof(target)) == sizeof(frame),
          "fragment Ethernet barrier");
}

static void wait_ack(unsigned lane, unsigned phase, uint64_t deadline) {
    while (!(acknowledged[lane] & (1U << phase))) {
        struct pollfd items[2] = {{.fd = packets[0], .events = POLLIN},
                                  {.fd = packets[1], .events = POLLIN}};
        check(poll(items, 2, 100) >= 0, "fragment barrier readiness");
        // Drain both real packet sockets while their fragments age concurrently.
        for (unsigned at = 0; at < 2; at++) {
            unsigned char frame[1600];
            ssize_t count;
            while ((count = recv(packets[at], frame, sizeof(frame), MSG_DONTWAIT)) >= 0) {
                if (count == 60 && !memcmp(frame, macs[at], 6) && frame[12] == 0x88 &&
                    frame[13] == 0xb7 && !memcmp(frame + 14, "IP6F", 4) && frame[18] == at &&
                    frame[19] < 8 && frame[20] == 1)
                    acknowledged[at] |= 1U << frame[19];
            }
            check(errno == EAGAIN, "bounded fragment control receive");
        }
        check(now() < deadline, "finite fragment barrier deadline");
    }
    printf("IPV6_FRAGMENTS_PHASE_PASS lane=%u phase=%u\n", lane, phase);
}

static void phase(unsigned number) {
    uint64_t deadline = now() + (number == 4 ? 100000000000ULL : 10000000000ULL);
    for (unsigned lane = 0; lane < 2; lane++)
        request(lane, number);
    for (unsigned lane = 0; lane < 2; lane++)
        wait_ack(lane, number, deadline);
}

static void configure(unsigned lane, int link) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "fragment address control");

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr field;
        struct in6_addr value;
    } message = {0};

    message.header = (struct nlmsghdr){sizeof(message), RTM_NEWADDR,
                                       NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 1, 0};
    message.address = (struct ifaddrmsg){AF_INET6, 64, IFA_F_NODAD, 0, indices[lane]};
    message.field = (struct rtattr){20, IFA_ADDRESS};
    message.value = address(lane, 2, 0, link).sin6_addr;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &message, sizeof(message), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(message),
          "explicit fragment fixture address");
    unsigned char reply[256];
    struct nlmsgerr result;
    ssize_t count = recv(fd, reply, sizeof(reply), 0);
    check(count >= (ssize_t)NLMSG_LENGTH(sizeof(result)) &&
              ((struct nlmsghdr*)reply)->nlmsg_type == NLMSG_ERROR,
          "address acknowledgement");
    memcpy(&result, NLMSG_DATA((struct nlmsghdr*)reply), sizeof(result));
    check(!result.error, "fragment fixture address result");
    close(fd);
}

static int wire_socket(unsigned lane, int type, unsigned local_port, unsigned peer_port, int link) {
    int fd = socket(AF_INET6, type | SOCK_CLOEXEC, type == SOCK_RAW ? IPPROTO_ICMPV6 : 0);
    check(fd >= 0, "real fragment receiver socket");
    char name[16];
    snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
          "fragment receiver device ownership");
    struct sockaddr_in6 local = address(lane, 2, local_port, link);
    struct sockaddr_in6 peer = address(lane, 1, peer_port, link);
    check(!bind(fd, (struct sockaddr*)&local, sizeof(local)) &&
              !connect(fd, (struct sockaddr*)&peer, sizeof(peer)),
          "fragment receiver tuple");
    return fd;
}

static void payload(unsigned lane, unsigned number, int fd, size_t size, int link, int echo) {
    struct pollfd item = {.fd = fd, .events = POLLIN};
    check(poll(&item, 1, 5000) == 1 && (item.revents & POLLIN), "fragment datagram readiness");
    struct sockaddr_in6 source, wanted = address(lane, 1,
                                                 echo   ? 0
                                                 : link ? 58011
                                                        : 57000 + lane,
                                                 link);
    socklen_t length = sizeof(source);
    check(recvfrom(fd, received, sizeof(received), MSG_DONTWAIT, (struct sockaddr*)&source,
                   &length) == (ssize_t)size,
          "complete reassembled datagram size");
    check(length == sizeof(source) && !memcmp(&source, &wanted, sizeof(source)),
          "original datagram source and scope");
    if (echo)
        check(received[0] == 129 && !received[1], "raw reassembled echo reply");
    for (size_t at = echo ? 4 : 0; at < size; at++) {
        unsigned pattern = number == 9 && at >= 8 ? 8 : number;
        unsigned offset = echo ? at - 4 : at;
        check(received[at] == (unsigned char)(offset * 17 + lane * 31 + pattern * 7),
              "every original reassembled application byte");
    }
    printf("IPV6_FRAGMENTS_CASE_PASS lane=%u case=%u bytes=%zu scope=%u\n", lane, number, size,
           link ? indices[lane] : 0);
}

static void quiet(void) {
    for (unsigned lane = 0; lane < 2; lane++) {
        int descriptors[] = {udp[lane], scoped[lane], raw[lane]};
        for (unsigned at = 0; at < 3; at++) {
            errno = 0;
            check(recv(descriptors[at], received, sizeof(received), MSG_DONTWAIT) == -1 &&
                      errno == EAGAIN,
                  "no duplicate, overlap, checksum or expired datagram");
        }
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (unsigned lane = 0; lane < 2; lane++) {
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        struct ifreq query = {0};
        snprintf(query.ifr_name, sizeof(query.ifr_name), "eth%u", lane);
        check(fd >= 0 && !ioctl(fd, SIOCGIFINDEX, &query), "actual interface index");
        indices[lane] = query.ifr_ifindex;
        check(!ioctl(fd, SIOCGIFHWADDR, &query), "actual interface MAC");
        memcpy(macs[lane], query.ifr_hwaddr.sa_data, 6);
        check(!ioctl(fd, SIOCGIFFLAGS, &query), "actual interface flags");
        query.ifr_flags |= IFF_UP;
        check(!ioctl(fd, SIOCSIFFLAGS, &query), "enable fragment interface");
        close(fd);
        packets[lane] = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(3));
        struct sockaddr_ll local = {
            .sll_family = AF_PACKET, .sll_protocol = htons(3), .sll_ifindex = indices[lane]};
        check(packets[lane] >= 0 && !bind(packets[lane], (struct sockaddr*)&local, sizeof(local)),
              "actual Ethernet control socket");
    }
    phase(0);
    for (unsigned lane = 0; lane < 2; lane++) {
        configure(lane, 0);
        configure(lane, 1);
        udp[lane] = wire_socket(lane, SOCK_DGRAM, 56000 + lane, 57000 + lane, 0);
        scoped[lane] = wire_socket(lane, SOCK_DGRAM, 58010, 58011, 1);
        raw[lane] = wire_socket(lane, SOCK_RAW, 0, 58, 0);
        struct icmp6_filter filter;
        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
        check(!setsockopt(raw[lane], IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)),
              "raw fragment receive filter");
        check(send(udp[lane], "", 0, 0) == 0, "real neighbor resolution trigger");
    }
    uint64_t basic_deadline = now() + 10000000000ULL;
    for (unsigned lane = 0; lane < 2; lane++)
        request(lane, 1);
    // Consume the earlier UDP datagram before the maximum datagram needs the
    // bounded receive queue. Both links retain the full maximum-payload case.
    for (unsigned lane = 0; lane < 2; lane++)
        payload(lane, 1, raw[lane], 19, 0, 1);
    for (unsigned lane = 0; lane < 2; lane++)
        payload(lane, 2, udp[lane], 57, 0, 0);
    for (unsigned lane = 0; lane < 2; lane++)
        payload(lane, 3, udp[lane], 65527, 0, 0);
    for (unsigned lane = 0; lane < 2; lane++)
        wait_ack(lane, 1, basic_deadline);
    phase(2);
    for (unsigned lane = 0; lane < 2; lane++) {
        payload(lane, 4, scoped[lane], 41, 1, 0);
        payload(lane, 5, udp[lane], 9, 0, 0);
        payload(lane, 6, udp[lane], 41, 0, 0);
    }
    phase(3);
    quiet();
    uint64_t began = now();
    phase(4);
    uint64_t elapsed = now() - began;
    printf("IPV6_FRAGMENTS_EXPIRY_ACK elapsed_ns=%llu\n", (unsigned long long)elapsed);
    check(elapsed >= 70000000000ULL && elapsed < 100000000000ULL,
          "complete real fragment expiry and suppression observation");
    printf("IPV6_FRAGMENTS_EXPIRY_PASS elapsed_ns=%llu\n", (unsigned long long)elapsed);
    phase(5);
    quiet();
    phase(6);
    for (unsigned lane = 0; lane < 2; lane++)
        payload(lane, 9, udp[lane], 41, 0, 0);
    phase(7);
    quiet();
    for (unsigned lane = 0; lane < 2; lane++) {
        close(raw[lane]);
        close(scoped[lane]);
        close(udp[lane]);
        close(packets[lane]);
    }
    puts("IPV6_FRAGMENTS_PASS nics=2 cases_each=7 maximum=65527 expiry_seconds=60");
    return 0;
}

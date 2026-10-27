// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP6_ZONE_ROUTE"
#define IPV6_BARRIER_PROTOCOL 0x88cd
#define IPV6_BARRIER_MAGIC "IP6G"
#include "ipv6_fixture.h"
#include <netinet/tcp.h>
#include <signal.h>

static unsigned local_port(unsigned lane, unsigned round) {
    return 52000 + lane * 100 + round * 10;
}

static unsigned remote_port(unsigned lane, unsigned round) {
    return 53000 + lane * 100 + round * 10;
}

static void device(int fd, unsigned lane, int bound) {
    char name[16] = {0};
    if (bound)
        snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
          "actual zone route device update");
}

static void phase(unsigned origin, unsigned round, unsigned step) {
    for (unsigned link = 0; link < 2; link++)
        barrier(link, origin * 64 + round * 16 + step);
    check(!fflush(stdout), "actual zone route phase record");
}

static void point(unsigned lane, unsigned round, const char* phase, int fd, int bound) {
    struct sockaddr_in6 local = {0}, peer = {0};
    socklen_t a = sizeof(local), b = sizeof(peer);
    check(!getsockname(fd, (struct sockaddr*)&local, &a) && a == sizeof(local) &&
              !getpeername(fd, (struct sockaddr*)&peer, &b) && b == sizeof(peer),
          "zone route actual names");
    struct sockaddr_in6 wanted = address(lane, 2, local_port(lane, round), 1);
    if (!bound)
        wanted.sin6_scope_id = 0;
    check(!memcmp(&local, &wanted, sizeof(local)), "retained zone route local tuple");
    wanted = address(lane, 1, remote_port(lane, round), 1);
    if (!bound)
        wanted.sin6_scope_id = 0;
    check(!memcmp(&peer, &wanted, sizeof(peer)), "retained zone route peer tuple");
    char binding[16] = {0};
    socklen_t capacity = sizeof(binding);
    check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, binding, &capacity),
          "zone route binding readback");
    printf("TCP6_ZONE_ROUTE_POINT lane=%u round=%u phase=%s hops=%d class=%d error=%d binding=%s "
           "capacity=%u index=%u local_scope=%u peer_scope=%u\n",
           lane, round, phase, get(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS),
           get(fd, IPPROTO_IPV6, IPV6_TCLASS), get(fd, SOL_SOCKET, SO_ERROR),
           binding[0] ? binding : "-", capacity, indices[lane], local.sin6_scope_id,
           peer.sin6_scope_id);
}

static int stream(unsigned lane, unsigned round) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    check(fd >= 0, "zone route stream");
    struct timeval timeout = {5, 0};
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
              !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)),
          "original five-second stream bounds");
    option(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    device(fd, lane, 1);
    struct sockaddr_in6 local = address(lane, 2, local_port(lane, round), 1);
    if (round)
        local.sin6_addr = in6addr_any;
    bind_address(fd, local);
    connect_address(fd, address(lane, 1, remote_port(lane, round), 1));
    return fd;
}

static void exchange(unsigned lane, unsigned round, int fd, unsigned tag) {
    unsigned char bytes[16], response[16];
    for (unsigned n = 0; n < 16; n++)
        bytes[n] = (lane * 53 + round * 31 + tag * 17 + n * 7) & 255;
    check(send(fd, bytes, 16, MSG_DONTWAIT | MSG_NOSIGNAL) == 16, "actual zone route TCP output");
    readable(fd, POLLIN);
    check(recv(fd, response, 16, MSG_DONTWAIT) == 16 && !memcmp(bytes, response, 16),
          "actual zone route TCP echo");
}

static void close_stream(int fd) {
    check(!shutdown(fd, SHUT_WR), "actual zone route half close");
    readable(fd, POLLIN);
    char byte;
    check(recv(fd, &byte, 1, 0) == 0 && !close(fd), "actual zone route EOF and final release");
}

static void normalize_link_local(unsigned lane) {
    struct sockaddr_in6 automatic = address(lane, 0, 0, 1);
    memcpy(automatic.sin6_addr.s6_addr + 8, macs[lane], 3);
    automatic.sin6_addr.s6_addr[8] ^= 2;
    automatic.sin6_addr.s6_addr[11] = 0xff;
    automatic.sin6_addr.s6_addr[12] = 0xfe;
    memcpy(automatic.sin6_addr.s6_addr + 13, macs[lane] + 3, 3);
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "scoped fixture address control");

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr field;
        struct in6_addr value;
    } message = {0};

    message.header =
        (struct nlmsghdr){sizeof(message), RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, 1, 0};
    message.address = (struct ifaddrmsg){AF_INET6, 64, 0, 0, indices[lane]};
    message.field = (struct rtattr){20, IFA_ADDRESS};
    message.value = automatic.sin6_addr;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &message, sizeof(message), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(message),
          "actual fixture MAC address removal request");
    unsigned char response[256];
    ssize_t size = recv(fd, response, sizeof(response), 0);
    struct nlmsgerr result;
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(result)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "scoped fixture address acknowledgement");
    memcpy(&result, NLMSG_DATA((struct nlmsghdr*)response), sizeof(result));
    check((!result.error || result.error == -EADDRNOTAVAIL || result.error == -ENOENT) &&
              !close(fd),
          "scoped fixture removes only its MAC-derived automatic candidate");
    int fresh = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    check(fresh >= 0, "scoped fixture candidate verification");
    device(fresh, lane, 1);
    errno = 0;
    int bound = bind(fresh, (struct sockaddr*)&automatic, sizeof(automatic));
    int error = errno;
    check(bound == -1 && error == EADDRNOTAVAIL && !close(fresh),
          "matching actual scoped source candidates");
    printf("TCP6_ZONE_ROUTE_FIXTURE lane=%u index=%u removed_error=%d bind_result=%d "
           "bind_errno=%d\n",
           lane, indices[lane], result.error, bound, error);
}

static void route(unsigned lane, unsigned metric, int add) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "finite source independent route control");

    struct {
        struct nlmsghdr header;
        struct rtmsg route;
        struct rtattr destination;
        struct in6_addr prefix;
        struct rtattr interface;
        uint32_t index;
        struct rtattr priority;
        uint32_t metric;
    } message = {0};

    message.header =
        (struct nlmsghdr){sizeof(message), add ? RTM_NEWROUTE : RTM_DELROUTE,
                          NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_EXCL : 0), 1, 0};
    message.route = (struct rtmsg){AF_INET6,      128,           0,           0, RT_TABLE_MAIN,
                                   RTPROT_STATIC, RT_SCOPE_LINK, RTN_UNICAST, 0};
    message.destination = (struct rtattr){20, RTA_DST};
    message.prefix = address(lane, 1, 0, 1).sin6_addr;
    message.interface = (struct rtattr){8, RTA_OIF};
    message.index = indices[lane];
    message.priority = (struct rtattr){8, RTA_PRIORITY};
    message.metric = metric;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &message, sizeof(message), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(message),
          "actual independent static route mutation");
    unsigned char response[256];
    ssize_t size = recv(fd, response, sizeof(response), 0);
    struct nlmsgerr acknowledgement;
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(acknowledgement)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "independent static route acknowledgement");
    memcpy(&acknowledgement, NLMSG_DATA((struct nlmsghdr*)response), sizeof(acknowledgement));
    check(!acknowledgement.error && !close(fd), "independent static route ownership succeeds");
}

static void route_snapshot(unsigned lane, unsigned round, const char* phase) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "finite route snapshot socket");

    struct {
        struct nlmsghdr header;
        struct rtmsg route;
    } request = {0};

    request.header =
        (struct nlmsghdr){sizeof(request), RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, 91, 0};
    request.route.rtm_family = AF_INET6;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &request, sizeof(request), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(request),
          "actual finite route dump request");
    for (;;) {
        unsigned char bytes[8192];
        int remaining = recv(fd, bytes, sizeof(bytes), 0);
        check(remaining > 0, "actual finite route dump response");
        for (struct nlmsghdr* item = (struct nlmsghdr*)bytes; NLMSG_OK(item, remaining);
             item = NLMSG_NEXT(item, remaining)) {
            if (item->nlmsg_type == NLMSG_DONE) {
                check(!close(fd), "finite route snapshot release");
                return;
            }
            check(item->nlmsg_type == RTM_NEWROUTE, "finite route snapshot row");
            printf("TCP6_ZONE_ROUTE_INVENTORY lane=%u round=%u phase=%s bytes=", lane, round,
                   phase);
            for (unsigned n = NLMSG_HDRLEN; n < item->nlmsg_len; n++)
                printf("%02x", ((unsigned char*)item)[n]);
            printf("\n");
        }
    }
}

static void one(unsigned lane, unsigned round) {
    route(lane, 20, 1);
    route(lane ^ 1, 10, 1);
    route_snapshot(lane, round, "configured");
    phase(lane, round, 1);
    int fd = stream(lane, round);
    point(lane, round, "connected", fd, 1);
    exchange(lane, round, fd, 0);
    phase(lane, round, 2);
    device(fd, lane, 0);
    option(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 37);
    option(fd, IPPROTO_IPV6, IPV6_TCLASS, 171);
    point(lane, round, "unbound", fd, 0);
    phase(lane, round, 3);
    exchange(lane, round, fd, 1);
    phase(lane, round, 4);
    route(lane ^ 1, 10, 0);
    route_snapshot(lane, round, "fallback");
    point(lane, round, "fallback", fd, 0);
    phase(lane, round, 5);
    exchange(lane, round, fd, 2);
    phase(lane, round, 6);
    route(lane ^ 1, 10, 1);
    route_snapshot(lane, round, "preferred");
    point(lane, round, "preferred", fd, 0);
    phase(lane, round, 7);
    exchange(lane, round, fd, 3);
    phase(lane, round, 8);
    device(fd, lane, 1);
    point(lane, round, "rebound", fd, 1);
    phase(lane, round, 9);
    exchange(lane, round, fd, 4);
    close_stream(fd);
    phase(lane, round, 10);
    route(lane ^ 1, 10, 0);
    route(lane, 20, 0);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")), "known zone route invocation");
    int control = fixture_interfaces();
    check(!close(control), "zone route fixture release");
    for (unsigned lane = 0; lane < 2; lane++)
        normalize_link_local(lane);
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned round = 0; round < 2; round++)
            one(lane, round);
    for (unsigned lane = 0; lane < 2; lane++)
        check(!close(packets[lane]), "zone route packet release");
    puts("TCP6_ZONE_ROUTE_PASS lanes=2 rounds_each=2 flows=4 exchanges=20");
    return 0;
}

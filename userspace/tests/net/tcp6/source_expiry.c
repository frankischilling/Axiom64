// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP6_SOURCE_EXPIRY"
#define IPV6_BARRIER_PROTOCOL 0x88cb
#define IPV6_BARRIER_MAGIC "IP6E"
#include "ipv6_fixture.h"
#include <fcntl.h>
#include <netinet/tcp.h>
#include <signal.h>

static void mutation(unsigned lane, unsigned host, int add) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "pending source control socket");

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr field;
        struct in6_addr value;
    } message = {0};

    message.header =
        (struct nlmsghdr){sizeof(message), add ? RTM_NEWADDR : RTM_DELADDR,
                          NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_EXCL : 0), 1, 0};
    message.address = (struct ifaddrmsg){AF_INET6, 64, IFA_F_NODAD, 0, indices[lane]};
    message.field = (struct rtattr){20, IFA_ADDRESS};
    message.value = address(lane, host, 0, 0).sin6_addr;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &message, sizeof(message), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(message),
          "actual pending source mutation");
    unsigned char response[256];
    ssize_t size = recv(fd, response, sizeof(response), 0);
    struct nlmsgerr result;
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(result)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "pending source mutation acknowledgement");
    memcpy(&result, NLMSG_DATA((struct nlmsghdr*)response), sizeof(result));
    check(!result.error && !close(fd), "pending source mutation succeeds");
}

static int stream(unsigned lane) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    check(fd >= 0, "pending source stream");
    struct timeval timeout = {5, 0};
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
              !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)),
          "original five-second stream bounds");
    char device[16];
    snprintf(device, sizeof(device), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1),
          "pending source bound device");
    option(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    return fd;
}

static void local_name(int fd, unsigned lane, unsigned host, unsigned port) {
    struct sockaddr_in6 value = {0}, expected = address(lane, host, port, 0);
    socklen_t capacity = sizeof(value);
    check(!getsockname(fd, (struct sockaddr*)&value, &capacity) && capacity == sizeof(value) &&
              !memcmp(&value, &expected, sizeof(value)),
          "pending source exact local name");
}

static void exchange(unsigned lane, unsigned round, int companion, int fd) {
    unsigned char bytes[16], response[16];
    for (unsigned n = 0; n < sizeof(bytes); n++)
        bytes[n] = (lane * 53 + round * 31 + companion * 17 + n * 7) & 255;
    check(send(fd, bytes, sizeof(bytes), MSG_NOSIGNAL) == sizeof(bytes),
          "pending source actual application output");
    readable(fd, POLLIN);
    check(recv(fd, response, sizeof(response), MSG_DONTWAIT) == sizeof(response) &&
              !memcmp(bytes, response, sizeof(bytes)),
          "pending source exact echo");
    check(!shutdown(fd, SHUT_WR), "pending source half-close");
    readable(fd, POLLIN);
    char byte;
    check(!recv(fd, &byte, 1, 0) && !close(fd), "pending source EOF and final description release");
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
            printf("TCP6_EXPIRY_ROUTE lane=%u round=%u phase=%s bytes=", lane, round, phase);
            for (unsigned n = NLMSG_HDRLEN; n < item->nlmsg_len; n++)
                printf("%02x", ((unsigned char*)item)[n]);
            printf("\n");
        }
    }
}

struct expiry_observation {
    int result, error;
};

static struct expiry_observation finite_expiry(unsigned lane, unsigned round) {
    barrier(lane, round * 16 + 6);
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "finite source control socket");

    struct {
        struct nlmsghdr header;
        struct ifaddrmsg address;
        struct rtattr field;
        struct in6_addr value;
        struct rtattr lifetime;
        struct ifa_cacheinfo cache;
    } message = {0};

    message.header = (struct nlmsghdr){sizeof(message), RTM_NEWADDR,
                                       NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE, 1, 0};
    message.address = (struct ifaddrmsg){AF_INET6, 64, IFA_F_NODAD, 0, indices[lane]};
    message.field = (struct rtattr){20, IFA_ADDRESS};
    message.value = address(lane, 2, 0, 0).sin6_addr;
    message.lifetime = (struct rtattr){20, IFA_CACHEINFO};
    message.cache.ifa_prefered = 2;
    message.cache.ifa_valid = 5;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    uint64_t began = now();
    check(sendto(fd, &message, sizeof(message), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(message),
          "actual finite lifetime request");
    unsigned char response[256];
    ssize_t size = recv(fd, response, sizeof(response), 0);
    struct nlmsgerr acknowledgement;
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(acknowledgement)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "finite lifetime acknowledgement");
    memcpy(&acknowledgement, NLMSG_DATA((struct nlmsghdr*)response), sizeof(acknowledgement));
    check(!acknowledgement.error && !close(fd), "finite lifetime replacement succeeds");
    barrier(lane, round * 16 + 7);
    struct sockaddr_in6 removed = address(lane, 2, 0, 0);
    unsigned successes = 0;
    struct expiry_observation observed;
    for (;;) {
        int fresh = stream(lane);
        errno = 0;
        observed.result = bind(fresh, (struct sockaddr*)&removed, sizeof(removed));
        observed.error = errno;
        check(!close(fresh), "finite lifetime fresh description release");
        if (observed.result == -1)
            break;
        check(observed.result == 0, "finite source remains bindable before expiry");
        successes++;
        check(now() - began < 8000000000ULL, "finite source expires within eight real seconds");
        struct timespec pause = {0, 10000000};
        check(!nanosleep(&pause, 0), "finite source observation poll");
    }
    check(successes > 0 && observed.error == EADDRNOTAVAIL,
          "real valid-to-expired transition rejects fresh binding");
    printf("TCP6_EXPIRY_LIFETIME lane=%u round=%u valid_seconds=5 preferred_seconds=2 "
           "bind_successes=%u result=%d error=%d elapsed_ns=%llu\n",
           lane, round, successes, observed.result, observed.error,
           (unsigned long long)(now() - began));
    barrier(lane, round * 16 + 8);
    check(!fflush(stdout), "finite source lifetime observations");
    return observed;
}

static void withdraw(unsigned lane, unsigned round, int fd) {
    mutation(lane, 3, 1);
    struct expiry_observation observed = finite_expiry(lane, round);
    route_snapshot(lane, round, "expired");
    int result = observed.result, error = observed.error;
    local_name(fd, lane, 2, 51000 + round * 10 + lane);
    int pending_error = get(fd, SOL_SOCKET, SO_ERROR);
    printf("TCP6_EXPIRY_ERROR lane=%u round=%u error=%d\n", lane, round, pending_error);
    check(!pending_error, "zero pending error with a surviving peer host route");
    printf("TCP6_EXPIRY_WITHDRAWN lane=%u round=%u bind_result=%d bind_errno=%d error=%d\n", lane,
           round, result, error, pending_error);
    int companion = stream(lane);
    struct sockaddr_in6 local = address(lane, 0, 51200 + round * 10 + lane, 0);
    local.sin6_addr = in6addr_any;
    bind_address(companion, local);
    connect_address(companion, address(lane, 1, 51300 + round * 10 + lane, 0));
    local_name(companion, lane, 3, 51200 + round * 10 + lane);
    exchange(lane, round, 1, companion);
}

static void start(unsigned lane, unsigned round, int fd) {
    int flags = fcntl(fd, F_GETFL);
    check(flags >= 0 && !fcntl(fd, F_SETFL, flags | O_NONBLOCK),
          "pending nonblocking connect mode");
    struct sockaddr_in6 remote = address(lane, 1, 51100 + round * 10 + lane, 0);
    errno = 0;
    int result = connect(fd, (struct sockaddr*)&remote, sizeof(remote));
    int error = errno;
    printf("TCP6_EXPIRY_CONNECT lane=%u round=%u result=%d error=%d\n", lane, round, result, error);
    check(result == -1 && error == EINPROGRESS, "actual asynchronous pending source connect");
    local_name(fd, lane, 2, 51000 + round * 10 + lane);
}

static void phase(unsigned lane, unsigned round, unsigned step) {
    barrier(lane, round * 16 + step);
    check(!fflush(stdout), "pending source observation flush");
}

static void one(unsigned lane, unsigned round) {
    route_snapshot(lane, round, "before");
    int fd = stream(lane);
    struct sockaddr_in6 local = address(lane, 2, 51000 + round * 10 + lane, 0);
    if (round == 2)
        local.sin6_addr = in6addr_any;
    bind_address(fd, local);
    if (round == 3)
        check(!listen(fd, 2), "pending passive source listener");
    phase(lane, round, 1);
    if (!round) {
        withdraw(lane, round, fd);
        phase(lane, round, 2);
        start(lane, round, fd);
    } else {
        if (round != 3)
            start(lane, round, fd);
        phase(lane, round, 2);
        withdraw(lane, round, fd);
    }
    phase(lane, round, 3);
    mutation(lane, 2, 1);
    phase(lane, round, 4);
    int connected = fd;
    if (round == 3) {
        readable(fd, POLLIN);
        connected = accept4(fd, 0, 0, SOCK_CLOEXEC);
        check(connected >= 0 && !close(fd), "actual passive child and final listener release");
    } else {
        readable(fd, POLLOUT);
        check(!get(fd, SOL_SOCKET, SO_ERROR), "pending source completed connection error");
        int flags = fcntl(fd, F_GETFL);
        check(flags >= 0 && !fcntl(fd, F_SETFL, flags & ~O_NONBLOCK),
              "pending source completed blocking mode");
    }
    local_name(connected, lane, 2, 51000 + round * 10 + lane);
    printf("TCP6_EXPIRY_ESTABLISHED lane=%u round=%u error=0\n", lane, round);
    exchange(lane, round, 0, connected);
    phase(lane, round, 5);
    mutation(lane, 3, 0);
}

static void independent_route(unsigned lane, int add) {
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
    message.prefix = address(lane, 1, 0, 0).sin6_addr;
    message.interface = (struct rtattr){8, RTA_OIF};
    message.index = indices[lane];
    message.priority = (struct rtattr){8, RTA_PRIORITY};
    message.metric = 64;
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

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")),
          "known pending source invocation");
    check(!close(fixture_interfaces()), "pending source interface control release");
    for (unsigned lane = 0; lane < 2; lane++) {
        independent_route(lane, 1);
        for (unsigned round = 0; round < 4; round++)
            one(lane, round);
        independent_route(lane, 0);
        check(!close(packets[lane]), "pending source packet control release");
    }
    static const char marker[] = "TCP6_SOURCE_EXPIRY_PASS lanes=2 rounds_each=4 flows_each=8 "
                                 "valid_seconds=5 preferred_seconds=2\n";
    check(write(1, marker, sizeof(marker) - 1) == sizeof(marker) - 1,
          "pending source actual completion");
    return 0;
}

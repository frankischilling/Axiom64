// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP6_PENDING_SOURCE"
#define IPV6_BARRIER_PROTOCOL 0x88ca
#define IPV6_BARRIER_MAGIC "IP6P"
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

static void withdraw(unsigned lane, unsigned round, int fd) {
    mutation(lane, 3, 1);
    mutation(lane, 2, 0);
    int fresh = stream(lane);
    struct sockaddr_in6 removed = address(lane, 2, 0, 0);
    errno = 0;
    int result = bind(fresh, (struct sockaddr*)&removed, sizeof(removed));
    int error = errno;
    check(result == -1 && error == EADDRNOTAVAIL && !close(fresh),
          "fresh pending source bind rejects withdrawn address");
    local_name(fd, lane, 2, 51000 + round * 10 + lane);
    check(!get(fd, SOL_SOCKET, SO_ERROR), "pending description keeps zero error after withdrawal");
    printf("TCP6_PENDING_WITHDRAWN lane=%u round=%u bind_result=%d bind_errno=%d error=0\n", lane,
           round, result, error);
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
    printf("TCP6_PENDING_CONNECT lane=%u round=%u result=%d error=%d\n", lane, round, result,
           error);
    check(result == -1 && error == EINPROGRESS, "actual asynchronous pending source connect");
    local_name(fd, lane, 2, 51000 + round * 10 + lane);
}

static void phase(unsigned lane, unsigned round, unsigned step) {
    barrier(lane, round * 16 + step);
    check(!fflush(stdout), "pending source observation flush");
}

static void one(unsigned lane, unsigned round) {
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
    printf("TCP6_PENDING_ESTABLISHED lane=%u round=%u error=0\n", lane, round);
    exchange(lane, round, 0, connected);
    phase(lane, round, 5);
    mutation(lane, 3, 0);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")),
          "known pending source invocation");
    check(!close(fixture_interfaces()), "pending source interface control release");
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned round = 0; round < 4; round++)
            one(lane, round);
        check(!close(packets[lane]), "pending source packet control release");
    }
    static const char marker[] = "TCP6_PENDING_SOURCE_PASS lanes=2 rounds_each=4 flows_each=8\n";
    check(write(1, marker, sizeof(marker) - 1) == sizeof(marker) - 1,
          "pending source actual completion");
    return 0;
}

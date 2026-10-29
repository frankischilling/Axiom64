// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP6_SCOPED_SOURCE_LIFETIME"
#define IPV6_BARRIER_PROTOCOL 0x88cc
#define IPV6_BARRIER_MAGIC "IP6Z"
#include "ipv6_fixture.h"
#include <netinet/tcp.h>
#include <signal.h>

static void mutation(unsigned lane, unsigned host, int add) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    check(fd >= 0, "source address control socket");

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
    message.value = address(lane, host, 0, 1).sin6_addr;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    check(sendto(fd, &message, sizeof(message), 0, (struct sockaddr*)&kernel, sizeof(kernel)) ==
              sizeof(message),
          "actual source mutation request");
    unsigned char response[256];
    ssize_t size = recv(fd, response, sizeof(response), 0);
    struct nlmsgerr result;
    check(size >= (ssize_t)NLMSG_LENGTH(sizeof(result)) &&
              ((struct nlmsghdr*)response)->nlmsg_type == NLMSG_ERROR,
          "actual source mutation acknowledgement");
    memcpy(&result, NLMSG_DATA((struct nlmsghdr*)response), sizeof(result));
    check(!result.error && !close(fd), "actual source mutation succeeds");
}

static void device(int fd, unsigned lane, int bound) {
    char name[16] = {0};
    if (bound)
        snprintf(name, sizeof(name), "eth%u", lane);
    check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
          "actual source stream device update");
}

static void name(int fd, unsigned lane, unsigned host, unsigned port) {
    struct sockaddr_in6 value = {0}, expected = address(lane, host, port, 1);
    socklen_t length = sizeof(value);
    check(!getsockname(fd, (struct sockaddr*)&value, &length) && length == sizeof(value) &&
              !memcmp(&value, &expected, sizeof(value)),
          "actual retained or fresh source name");
}

static int stream(unsigned lane, unsigned round, int companion) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    check(fd >= 0, "source lifetime stream");
    struct timeval timeout = {5, 0};
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
              !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)),
          "original five-second stream bounds");
    device(fd, lane, 1);
    option(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    unsigned port = (companion ? 50200 : 50000) + round * 10;
    struct sockaddr_in6 local = address(lane, companion || round ? 0 : 2, port, 1);
    if (companion || round)
        local.sin6_addr = in6addr_any;
    bind_address(fd, local);
    connect_address(fd, address(lane, 1, (companion ? 50300 : 50100) + round * 10, 1));
    name(fd, lane, companion ? 3 : 2, port);
    return fd;
}

static void point(unsigned lane, unsigned round, const char* phase, int fd) {
    int hops = get(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS);
    int traffic = get(fd, IPPROTO_IPV6, IPV6_TCLASS);
    int error = get(fd, SOL_SOCKET, SO_ERROR);
    char binding[16] = {0}, record[384];
    socklen_t capacity = sizeof(binding);
    check(!getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, binding, &capacity),
          "scoped device readback");
    struct sockaddr_in6 local = {0}, peer = {0};
    socklen_t local_length = sizeof(local), peer_length = sizeof(peer);
    check(!getsockname(fd, (struct sockaddr*)&local, &local_length) &&
              local_length == sizeof(local) &&
              !getpeername(fd, (struct sockaddr*)&peer, &peer_length) &&
              peer_length == sizeof(peer),
          "actual scoped local and peer names");
    struct sockaddr_in6 expected_local = address(lane, 2, 50000 + round * 10, 1);
    struct sockaddr_in6 expected_peer = address(lane, 1, 50100 + round * 10, 1);
    if (!strcmp(phase, "device-cleared"))
        expected_local.sin6_scope_id = expected_peer.sin6_scope_id = 0;
    check(!memcmp(&local, &expected_local, sizeof(local)) &&
              !memcmp(&peer, &expected_peer, sizeof(peer)),
          "actual scoped tuple and native-derived device-controlled zones");
    int length = snprintf(
        record, sizeof(record),
        "TCP6_SCOPED_SOURCE_POINT lane=%u round=%u phase=%s hops=%d class=%d error=%d binding=%s "
        "capacity=%u index=%u local_scope=%u peer_scope=%u\n",
        lane, round, phase, hops, traffic, error, binding[0] ? binding : "-", capacity,
        indices[lane], local.sin6_scope_id, peer.sin6_scope_id);
    check(length > 0 && (size_t)length < sizeof(record) && write(1, record, length) == length,
          "complete actual scoped state observation");
}

static void send_bytes(unsigned lane, unsigned round, int fd, unsigned tag, int echo) {
    unsigned char bytes[16], response[16];
    for (unsigned n = 0; n < sizeof(bytes); n++)
        bytes[n] = (lane * 53 + round * 31 + tag * 17 + n * 7) & 255;
    check(send(fd, bytes, sizeof(bytes), MSG_DONTWAIT | MSG_NOSIGNAL) == sizeof(bytes),
          "actual source lifetime application output");
    if (echo) {
        readable(fd, POLLIN);
        check(recv(fd, response, sizeof(response), MSG_DONTWAIT) == sizeof(response) &&
                  !memcmp(bytes, response, sizeof(bytes)),
              "actual source lifetime echo");
    }
}

static void phase(unsigned lane, unsigned round, unsigned step) {
    barrier(lane, round * 16 + step);
    check(!fflush(stdout), "source phase record");
}

static void close_stream(int fd) {
    check(!shutdown(fd, SHUT_WR), "source stream application half-close");
    readable(fd, POLLIN);
    char byte;
    check(recv(fd, &byte, 1, 0) == 0 && !close(fd), "source stream EOF and final release");
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
    printf("TCP6_SCOPED_SOURCE_FIXTURE lane=%u index=%u removed_error=%d bind_result=%d "
           "bind_errno=%d\n",
           lane, indices[lane], result.error, bound, error);
}

static void other_zone(unsigned lane, unsigned round, int result, int error) {
    unsigned other = lane ^ 1;
    int fresh = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    check(fresh >= 0, "independent same-address other-zone socket");
    device(fresh, other, 1);
    struct sockaddr_in6 local = address(other, 2, 0, 1);
    bind_address(fresh, local);
    socklen_t size = sizeof(local);
    check(!getsockname(fresh, (struct sockaddr*)&local, &size) && size == sizeof(local) &&
              local.sin6_scope_id == indices[other] && local.sin6_port && !close(fresh),
          "same address stays valid in the other zone");
    printf("TCP6_SCOPED_SOURCE_BIND lane=%u round=%u result=%d error=%d other_index=%u "
           "other_scope=%u\n",
           lane, round, result, error, indices[other], local.sin6_scope_id);
}

static void one(unsigned lane, unsigned round) {
    phase(lane, round, 1);
    int fd = stream(lane, round, 0);
    point(lane, round, "connected", fd);
    send_bytes(lane, round, fd, 0, 1);
    phase(lane, round, 8);
    device(fd, lane, 0);
    point(lane, round, "device-cleared", fd);
    phase(lane, round, 9);
    device(fd, lane, 1);
    point(lane, round, "device-restored", fd);
    phase(lane, round, 10);
    mutation(lane, 3, 1);
    mutation(lane, 2, 0);
    int fresh = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    check(fresh >= 0, "fresh withdrawn-source bind control");
    device(fresh, lane, 1);
    struct sockaddr_in6 removed = address(lane, 2, 0, 1);
    errno = 0;
    int result = bind(fresh, (struct sockaddr*)&removed, sizeof(removed));
    int error = errno;
    check(result == -1 && error == EADDRNOTAVAIL && !close(fresh),
          "withdrawn address rejects a fresh explicit bind");
    other_zone(lane, round, result, error);
    point(lane, round, "source-removed", fd);
    phase(lane, round, 2);
    int companion = stream(lane, round, 1);
    send_bytes(lane, round, companion, 9, 1);
    close_stream(companion);
    send_bytes(lane, round, fd, 1, 0);
    phase(lane, round, 3);
    option(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, 37);
    option(fd, IPPROTO_IPV6, IPV6_TCLASS, 171);
    point(lane, round, "class-cleared", fd);
    send_bytes(lane, round, fd, 2, 0);
    phase(lane, round, 4);
    point(lane, round, "source-held", fd);
    send_bytes(lane, round, fd, 3, 0);
    phase(lane, round, 5);
    mutation(lane, 2, 1);
    phase(lane, round, 6);
    point(lane, round, "source-restored", fd);
    send_bytes(lane, round, fd, 4, 1);
    close_stream(fd);
    phase(lane, round, 7);
    mutation(lane, 3, 0);
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")),
          "known source probe invocation");
    int control = fixture_interfaces();
    check(!close(control), "source interface control release");
    for (unsigned lane = 0; lane < 2; lane++)
        normalize_link_local(lane);
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned round = 0; round < 2; round++)
            one(lane, round);
        check(!close(packets[lane]), "source packet control release");
    }
    static const char marker[] =
        "TCP6_SCOPED_SOURCE_LIFETIME_PASS lanes=2 rounds_each=2 flows_each=4 "
        "data_each=12 withdrawn_each=6\n";
    check(write(1, marker, sizeof(marker) - 1) == sizeof(marker) - 1, "source probe completion");
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP6_PMTU"
#define IPV6_BARRIER_PROTOCOL 0x88c2
#define IPV6_BARRIER_MAGIC "IP6M"
#include "../ipv6_fixture.h"
#include <netinet/tcp.h>
#include <signal.h>

enum { transfer_bytes = 4096, scenarios = 22 };

static unsigned char pattern(unsigned position, unsigned lane, unsigned scenario,
                             unsigned direction) {
    return (unsigned char)((position * 29) ^ (position >> 7) ^ (lane * 53) ^ (scenario * 97) ^
                           (direction * 41));
}

static int peer_mss(unsigned scenario) {
    if (scenario == 4 || scenario == 5)
        return 536;
    if (scenario == 6)
        return 1200;
    if (scenario == 7)
        return 1220;
    if (scenario == 8)
        return 1280;
    return 1440;
}

static int ignores(unsigned scenario) {
    return scenario == 2 || scenario == 3 || (scenario >= 4 && scenario <= 7) || scenario == 20;
}

static void metrics(int fd, unsigned lane, unsigned scenario, int recovered) {
    int mtu_fd = create(SOCK_DGRAM);
    bind_address(mtu_fd, address(lane, 2, 0, 0));
    connect_address(mtu_fd, address(lane, 10 + scenario, 49800, 0));
    int mtu = get(mtu_fd, IPPROTO_IPV6, IPV6_MTU);
    int mss = get(fd, IPPROTO_TCP, TCP_MAXSEG);
    int wanted_mss = recovered && !ignores(scenario) ? 1220 : peer_mss(scenario);
    int wanted_mtu = recovered && !ignores(scenario) ? 1280 : 1500;
    printf("TCP6_PMTU_METRIC lane=%u case=%u stage=%s mss=%d mtu=%d\n", lane, scenario,
           recovered ? "recovered" : "connected", mss, mtu);
    check(mss == wanted_mss && mtu == wanted_mtu, "native compared TCP6 MSS and route MTU");
    check(close(mtu_fd) == 0, "MTU query description release");
}

static void flow(unsigned lane, unsigned scenario) {
    barrier(lane, scenario * 3 + 1);
    int fd = create(SOCK_STREAM);
    struct timeval timeout = {20, 0};
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
              !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)),
          "bounded stream I/O");
    option(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    int passive = scenario == 1 || scenario == 3 || scenario == 5;
    struct sockaddr_in6 local = address(lane, 2, passive ? 45000 + scenario * 20 + lane : 0, 0);
    struct sockaddr_in6 remote = address(lane, 10 + scenario, 44000 + scenario * 20 + lane, 0);
    bind_address(fd, local);
    if (passive) {
        check(listen(fd, 2) == 0, "PMTU listener");
        printf("TCP6_PMTU_LISTEN lane=%u case=%u\n", lane, scenario);
        struct sockaddr_in6 actual;
        socklen_t length = sizeof(actual);
        int child = accept4(fd, (struct sockaddr*)&actual, &length, SOCK_CLOEXEC);
        check(child >= 0 && length == sizeof(actual) && !memcmp(&actual, &remote, sizeof(actual)),
              "accepted full IPv6 peer identity");
        check(close(fd) == 0, "PMTU listener release");
        fd = child;
        check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
                  !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)),
              "accepted bounded stream I/O");
    } else {
        connect_address(fd, remote);
    }
    metrics(fd, lane, scenario, 0);
    unsigned char data[transfer_bytes];
    for (unsigned at = 0; at < sizeof(data); at++)
        data[at] = pattern(at, lane, scenario, 0);
    size_t sent = 0, received = 0;
    while (sent < sizeof(data)) {
        ssize_t count = send(fd, data + sent, sizeof(data) - sent, MSG_NOSIGNAL);
        check(count > 0 && (size_t)count <= sizeof(data) - sent, "complete queued PMTU stream");
        sent += (size_t)count;
    }
    while (received < sizeof(data)) {
        ssize_t count = recv(fd, data + received, sizeof(data) - received, 0);
        check(count > 0 && (size_t)count <= sizeof(data) - received,
              "complete recovered PMTU stream");
        received += (size_t)count;
    }
    for (unsigned at = 0; at < sizeof(data); at++)
        check(data[at] == pattern(at, lane, scenario, 1), "exact PMTU reply bytes");
    barrier(lane, scenario * 3 + 2);
    metrics(fd, lane, scenario, 1);
    check(get(fd, SOL_SOCKET, SO_ERROR) == 0, "PTB preserves established stream");
    check(shutdown(fd, SHUT_WR) == 0 && recv(fd, data, 1, 0) == 0, "acknowledged PMTU half-close");
    check(close(fd) == 0, "PMTU stream release");
    barrier(lane, scenario * 3 + 3);
    printf("TCP6_PMTU_FLOW_PASS lane=%u case=%u bytes_each=%u\n", lane, scenario, transfer_bytes);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")), "known fixture invocation");
    check(close(fixture_interfaces()) == 0, "PMTU interface setup");
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned scenario = 0; scenario < scenarios; scenario++)
            flow(lane, scenario);
    puts("TCP6_PMTU_PASS lanes=2 cases_each=22 bytes_each=4096");
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP6_ERRORS"
#define IPV6_BARRIER_PROTOCOL 0x88c3
#define IPV6_BARRIER_MAGIC "IP6E"
#include "../ipv6_fixture.h"
#include <netinet/tcp.h>
#include <signal.h>

enum { classes = 13, scenarios = classes * 4 + 10 };

static const int errors[classes] = {101, 13, 113, 113, 111, 13, 13, 71, 113, 113, 71, 71, 71};
static const int fatal[classes] = {0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1};
static int native;

static int shared_error(int fd, int alias) {
    int value = get(alias, SOL_SOCKET, SO_ERROR);
    check(get(fd, SOL_SOCKET, SO_ERROR) == 0, "error consumption through shared description");
    return value;
}

static void flow(unsigned lane, unsigned scenario) {
    unsigned mode = scenario / classes, kind = scenario % classes;
    int passive = mode == 1;
    barrier(lane, scenario * 3 + 1);
    int fd = create(SOCK_STREAM | ((mode == 0 || mode == 4) ? SOCK_NONBLOCK : 0));
    struct timeval timeout = {5, 0};
    check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
              !setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)),
          "bounded error stream I/O");
    option(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    bind_address(fd, address(lane, 2, 45000 + scenario * 20 + lane, 0));
    struct sockaddr_in6 remote = address(lane, 10 + scenario, 44000 + scenario * 20 + lane, 0);
    if (passive) {
        check(!listen(fd, 2), "error listener");
        printf("TCP6_ERRORS_LISTEN lane=%u case=%u\n", lane, scenario);
    } else if (mode == 0 || mode == 4) {
        check(connect(fd, (struct sockaddr*)&remote, sizeof(remote)) == -1 && errno == EINPROGRESS,
              "pending IPv6 active open");
    } else {
        connect_address(fd, remote);
        check(send(fd, "one", 3, MSG_NOSIGNAL) == 3, "owned unacknowledged error quote bytes");
    }
    barrier(lane, scenario * 3 + 2);
    if (passive) {
        check(get(fd, SOL_SOCKET, SO_ERROR) == 0, "listener survives child error");
        readable(fd, POLLIN);
        struct sockaddr_in6 actual;
        socklen_t length = sizeof(actual);
        int child = accept4(fd, (struct sockaddr*)&actual, &length, SOCK_CLOEXEC);
        remote.sin6_port = htons(44000 + scenario * 20 + lane + (fatal[kind] ? 2 : 0));
        check(child >= 0 && length == sizeof(actual) && !memcmp(&actual, &remote, sizeof(actual)),
              "native compared passive request generation");
        check(get(fd, SOL_SOCKET, SO_ERROR) == 0 && !close(fd), "healthy listener release");
        fd = child;
        check(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)),
              "accepted stream deadline");
    }
    int alias = dup(fd);
    check(alias >= 0, "shared error description alias");
    int reported = 0;
    struct pollfd ready = {.fd = fd, .events = POLLIN | POLLOUT};
    // Native Linux dispatches this quote despite its altered version nibble.
    // Keep the measured difference visible; Axiom64's bounded quote decoder
    // still rejects it. This case does not establish parser equivalence.
    if (mode == 0 || (native && scenario == 61)) {
        check(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLERR), "failed connect readiness");
        reported = shared_error(fd, alias);
        printf("TCP6_ERRORS_ACTIVE lane=%u case=%u error=%d events=%x\n", lane, scenario, reported,
               ready.revents);
        check(reported == (mode == 0 ? errors[kind] : ECONNREFUSED),
              "native compared active error");
    } else {
        if (mode == 4) {
            ready.events = POLLOUT;
            check(poll(&ready, 1, 50) == 0 && shared_error(fd, alias) == 0,
                  "invalid quote leaves active open pending");
            check(poll(&ready, 1, 3000) == 1 && !(ready.revents & POLLERR) &&
                      shared_error(fd, alias) == 0,
                  "actual handshake after ignored error");
        } else if (mode == 2 || mode == 3) {
            ready.events = POLLIN;
            check(poll(&ready, 1, 0) == 0, "soft error does not terminate established stream");
            if (mode == 2) {
                reported = shared_error(fd, alias);
                check(reported == errors[kind], "native compared established soft error");
            }
        } else {
            check(shared_error(fd, alias) == 0, "healthy accepted description");
        }
        check(!close(fd), "original descriptor retirement retains alias");
        fd = alias;
        alias = -1;
        const char* data = mode == 2 || mode == 3 ? "two" : "one";
        check(send(fd, data, 3, MSG_NOSIGNAL) == 3, "stream survives quoted error");
        char reply;
        readable(fd, POLLIN);
        check(recv(fd, &reply, 1, 0) == 1 && reply == 'K' && get(fd, SOL_SOCKET, SO_ERROR) == 0,
              "acknowledged progress clears soft error");
        check(!shutdown(fd, SHUT_WR), "error stream half-close");
        readable(fd, POLLIN);
        check(recv(fd, &reply, 1, 0) == 0, "acknowledged peer half-close");
    }
    check(!close(fd) && (alias < 0 || !close(alias)), "error descriptions released");
    barrier(lane, scenario * 3 + 3);
    printf("TCP6_ERRORS_FLOW_PASS lane=%u case=%u mode=%u error=%d replacement=%d\n", lane,
           scenario, mode, reported, passive && fatal[kind]);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")), "known fixture invocation");
    native = argc == 2;
    check(!close(fixture_interfaces()), "error interface setup");
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned scenario = 0; scenario < scenarios; scenario++)
            flow(lane, scenario);
    puts("TCP6_ERRORS_PASS lanes=2 cases_each=62");
    return 0;
}

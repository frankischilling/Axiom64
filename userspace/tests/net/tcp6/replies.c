// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "TCP6_REPLIES"
#define IPV6_BARRIER_PROTOCOL 0x88c5
#define IPV6_BARRIER_MAGIC "IP6R"
#include "../ipv6_fixture.h"
#include <signal.h>

enum { reply_cases = 10, scenarios = reply_cases * 2 };

static void one(unsigned lane, unsigned scenario) {
    unsigned kind = scenario % reply_cases;
    int link = scenario < reply_cases;
    int fd = create(SOCK_STREAM | SOCK_NONBLOCK);
    option(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    struct sockaddr_in6 local = {.sin6_family = AF_INET6, .sin6_port = htons(49460)};
    if (kind == 7 || kind == 8) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", kind == 7 ? lane : 1 - lane);
        check(!setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name) + 1),
              "actual listener interface binding");
    } else if (kind == 9)
        local = address(lane, 2, 49460, link);
    bind_address(fd, local);
    struct sockaddr_in6 actual;
    socklen_t size = sizeof(actual);
    check(!getsockname(fd, (struct sockaddr*)&actual, &size) && size == sizeof(actual) &&
              !memcmp(&actual, &local, sizeof(actual)),
          "exact original listener or closed-port owner");
    if (kind < 6) {
        check(!close(fd), "release the actual closed-port owner before input");
        fd = -1;
    } else
        check(!listen(fd, 2), "actual wildcard or scoped listener");
    barrier(lane, scenario * 2 + 1);
    if (fd >= 0) {
        struct pollfd event = {.fd = fd, .events = POLLIN};
        check(poll(&event, 1, 0) == 0 && get(fd, SOL_SOCKET, SO_ERROR) == 0,
              "invalid ACK cannot create or fail a listener child");
        errno = 0;
        check(accept4(fd, NULL, NULL, SOCK_CLOEXEC) == -1 && errno == EAGAIN,
              "no accepted child after the complete error observation");
        check(!close(fd), "listener and binding released");
    }
    char record[192];
    int length =
        snprintf(record, sizeof(record),
                 "TCP6_REPLIES_CASE_PASS lane=%u case=%u scope=%s listener=%u index=%u\n", lane,
                 scenario, link ? "link" : "global", kind < 6 ? 0 : kind - 5, indices[lane]);
    check(length > 0 && (size_t)length < sizeof(record) &&
              write(STDOUT_FILENO, record, (size_t)length) == length,
          "complete reply observation record");
    barrier(lane, scenario * 2 + 2);
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    alarm(120);
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--native")), "known reply invocation");
    check(!close(fixture_interfaces()), "reply interface setup");
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned scenario = 0; scenario < scenarios; scenario++)
            one(lane, scenario);
        check(!close(packets[lane]), "reply Ethernet channel released");
    }
    const char complete[] = "TCP6_REPLIES_PASS lanes=2 cases_each=20 quiet_ms=50\n";
    check(write(STDOUT_FILENO, complete, sizeof(complete) - 1) == sizeof(complete) - 1,
          "complete reply result record");
    return 0;
}

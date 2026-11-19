// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "EPOLL_NESTED_FAIL line=%d errno=%d %s\n", __LINE__, errno,            \
                    #condition);                                                                   \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static int open_epoll(void) {
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    return epoll;
}

static void watch(int epoll, int fd, unsigned token, uint32_t events) {
    struct epoll_event event = {.events = events, .data.u32 = token};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &event) == 0);
}

static void expect_mask(int epoll, unsigned token, uint32_t mask) {
    struct epoll_event event;
    CHECK(epoll_wait(epoll, &event, 1, 1000) == 1);
    CHECK(event.data.u32 == token && event.events == mask);
}

static void expect_event(int epoll, unsigned token) {
    expect_mask(epoll, token, EPOLLIN);
}

static void expect_empty(int epoll) {
    struct epoll_event event;
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
}

static void check_poll_and_select(int epoll, int expected) {
    struct pollfd entry = {.fd = epoll, .events = POLLIN | POLLOUT | POLLRDNORM};
    CHECK(poll(&entry, 1, 0) == expected);
    CHECK(entry.revents == (expected ? POLLIN | POLLRDNORM : 0));
    fd_set readable, writable;
    FD_ZERO(&readable);
    FD_ZERO(&writable);
    FD_SET(epoll, &readable);
    FD_SET(epoll, &writable);
    struct timeval deadline = {0};
    CHECK(select(epoll + 1, &readable, &writable, NULL, &deadline) == expected);
    CHECK(!!FD_ISSET(epoll, &readable) == expected && !FD_ISSET(epoll, &writable));
}

static void readiness_and_aliases(void) {
    int tube[2];
    CHECK(pipe2(tube, O_NONBLOCK) == 0);
    int inner = open_epoll(), outer = open_epoll();
    watch(inner, tube[0], 31, EPOLLIN | EPOLLET);
    watch(outer, inner, 32, EPOLLIN | EPOLLET);
    int alias = dup(inner);
    CHECK(alias >= 0 && close(inner) == 0);
    expect_empty(outer);
    check_poll_and_select(alias, 0);
    check_poll_and_select(outer, 0);

    CHECK(write(tube[1], "A", 1) == 1);
    check_poll_and_select(alias, 1);
    check_poll_and_select(outer, 1);
    expect_event(outer, 32);
    expect_empty(outer);
    check_poll_and_select(alias, 1);
    CHECK(write(tube[1], "B", 1) == 1);
    expect_event(outer, 32);

    int normal = open_epoll();
    watch(normal, alias, 34, EPOLLRDNORM | EPOLLET);
    expect_mask(normal, 34, EPOLLRDNORM);
    expect_empty(normal);
    CHECK(close(normal) == 0);

    int level = open_epoll();
    watch(level, alias, 33, EPOLLIN);
    expect_event(level, 33);
    expect_event(level, 33);
    expect_event(alias, 31);
    check_poll_and_select(alias, 0);
    expect_empty(level);
    char bytes[2];
    CHECK(read(tube[0], bytes, sizeof(bytes)) == 2 && memcmp(bytes, "AB", 2) == 0);
    CHECK(write(tube[1], "C", 1) == 1 && close(alias) == 0);
    expect_empty(level);
    expect_empty(outer);
    CHECK(close(level) == 0 && close(outer) == 0 && close(tube[0]) == 0 && close(tube[1]) == 0);
    puts("EPOLL_NESTED_CASE readiness-and-aliases");
}

static void depth_and_cycles(int legacy) {
    int epoll[6];
    for (unsigned i = 0; i < 6; i++)
        epoll[i] = open_epoll();
    for (unsigned i = 0; i < 4; i++)
        watch(epoll[i], epoll[i + 1], i + 11, EPOLLIN | EPOLLET);
    struct epoll_event event = {.events = EPOLLIN};
    if (legacy) {
        CHECK(epoll_ctl(epoll[4], EPOLL_CTL_ADD, epoll[5], &event) == 0);
        CHECK(epoll_ctl(epoll[4], EPOLL_CTL_DEL, epoll[5], NULL) == 0);
        CHECK(epoll_ctl(epoll[5], EPOLL_CTL_ADD, epoll[0], &event) == 0);
        CHECK(epoll_ctl(epoll[5], EPOLL_CTL_DEL, epoll[0], NULL) == 0);
    } else {
        CHECK(epoll_ctl(epoll[4], EPOLL_CTL_ADD, epoll[5], &event) == -1 && errno == ELOOP);
        CHECK(epoll_ctl(epoll[5], EPOLL_CTL_ADD, epoll[0], &event) == -1 && errno == ELOOP);
    }
    CHECK(epoll_ctl(epoll[3], EPOLL_CTL_ADD, epoll[1], &event) == -1 && errno == ELOOP);
    event.events = EPOLLIN | EPOLLEXCLUSIVE;
    CHECK(epoll_ctl(epoll[5], EPOLL_CTL_ADD, epoll[4], &event) == -1 && errno == EINVAL);

    int tube[2];
    CHECK(pipe2(tube, O_NONBLOCK) == 0);
    watch(epoll[4], tube[0], 15, EPOLLIN | EPOLLET);
    expect_empty(epoll[0]);
    CHECK(write(tube[1], "D", 1) == 1);
    for (unsigned i = 0; i < 5; i++)
        expect_event(epoll[i], i + 11);
    char data = 0;
    CHECK(read(tube[0], &data, 1) == 1 && data == 'D');
    expect_empty(epoll[0]);
    for (unsigned i = 0; i < 6; i++)
        CHECK(close(epoll[i]) == 0);
    CHECK(close(tube[0]) == 0 && close(tube[1]) == 0);
    puts("EPOLL_NESTED_CASE depth-and-cycles");
}

static void shared_descendant(void) {
    int tube[2];
    CHECK(pipe2(tube, O_NONBLOCK) == 0);
    int top = open_epoll(), left = open_epoll(), right = open_epoll(), leaf = open_epoll();
    watch(top, left, 41, EPOLLIN | EPOLLET);
    watch(top, right, 42, EPOLLIN | EPOLLET);
    watch(left, leaf, 43, EPOLLIN | EPOLLET);
    watch(right, leaf, 44, EPOLLIN | EPOLLET);
    watch(leaf, tube[0], 45, EPOLLIN | EPOLLET);
    CHECK(write(tube[1], "G", 1) == 1);
    struct epoll_event batch[2];
    CHECK(epoll_wait(top, batch, 2, 1000) == 2);
    CHECK(batch[0].events == EPOLLIN && batch[1].events == EPOLLIN);
    CHECK((batch[0].data.u32 == 41 && batch[1].data.u32 == 42) ||
          (batch[0].data.u32 == 42 && batch[1].data.u32 == 41));
    expect_empty(top);
    expect_event(left, 43);
    expect_event(right, 44);
    expect_event(leaf, 45);
    char data = 0;
    CHECK(read(tube[0], &data, 1) == 1 && data == 'G');
    CHECK(close(tube[0]) == 0 && close(tube[1]) == 0);
    CHECK(close(leaf) == 0 && close(left) == 0 && close(right) == 0 && close(top) == 0);
    puts("EPOLL_NESTED_CASE shared-descendant");
}

static void timer_and_signal(void) {
    int outer = open_epoll(), inner = open_epoll();
    watch(outer, inner, 51, EPOLLIN | EPOLLET);
    int timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    CHECK(timer >= 0);
    watch(inner, timer, 52, EPOLLIN | EPOLLONESHOT);
    struct itimerspec interval = {.it_value.tv_nsec = 60000000};
    CHECK(timerfd_settime(timer, 0, &interval, NULL) == 0);
    struct pollfd entry = {.fd = outer, .events = POLLIN};
    CHECK(poll(&entry, 1, 1000) == 1 && entry.revents == POLLIN);
    expect_event(outer, 51);
    expect_event(inner, 52);
    uint64_t expirations = 0;
    CHECK(read(timer, &expirations, sizeof(expirations)) == sizeof(expirations) &&
          expirations == 1);
    CHECK(close(timer) == 0);
    expect_empty(outer);
    expect_empty(inner);

    sigset_t mask, original;
    CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGUSR1) == 0);
    CHECK(sigprocmask(SIG_BLOCK, &mask, &original) == 0);
    int signal = signalfd(-1, &mask, SFD_NONBLOCK);
    CHECK(signal >= 0);
    watch(inner, signal, 53, EPOLLIN | EPOLLET);
    CHECK(kill(getpid(), SIGUSR1) == 0);
    expect_event(outer, 51);
    expect_event(inner, 53);
    struct signalfd_siginfo info;
    CHECK(read(signal, &info, sizeof(info)) == sizeof(info) && info.ssi_signo == SIGUSR1);
    expect_empty(outer);
    CHECK(sigprocmask(SIG_SETMASK, &original, NULL) == 0);
    CHECK(close(signal) == 0 && close(inner) == 0 && close(outer) == 0);
    puts("EPOLL_NESTED_CASE timer-and-signal");
}

static void round_robin(void) {
    int epoll = open_epoll(), tubes[3][2];
    for (unsigned n = 0; n < 3; n++) {
        CHECK(pipe2(tubes[n], O_NONBLOCK) == 0);
        watch(epoll, tubes[n][0], n, EPOLLIN);
        CHECK(write(tubes[n][1], "R", 1) == 1);
    }
    for (unsigned round = 0; round < 4; round++) {
        unsigned seen = 0;
        for (unsigned i = 0; i < 3; i++) {
            struct epoll_event event;
            CHECK(epoll_wait(epoll, &event, 1, 0) == 1);
            CHECK(event.events == EPOLLIN && event.data.u32 < 3);
            seen |= 1u << event.data.u32;
        }
        CHECK(seen == 7);
    }
    for (unsigned n = 0; n < 3; n++)
        CHECK(close(tubes[n][0]) == 0 && close(tubes[n][1]) == 0);
    CHECK(close(epoll) == 0);
    puts("EPOLL_NESTED_CASE round-robin");
}

int main(int argc, char** argv) {
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    alarm(15);
    int legacy = 0;
    for (int arg = 1; arg < argc; arg++) {
        if (strcmp(argv[arg], "--ordinary") == 0)
            CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        else {
            CHECK(strcmp(argv[arg], "--legacy-depth") == 0);
            legacy = 1;
        }
    }
    readiness_and_aliases();
    depth_and_cycles(legacy);
    shared_descendant();
    timer_and_signal();
    round_robin();
    printf("EPOLL_NESTED_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}

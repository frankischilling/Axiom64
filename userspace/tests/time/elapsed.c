// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t alarm_seen;

static void alarm_handler(int number) {
    (void)number;
    alarm_seen = 1;
}

static void require(int condition, const char* operation) {
    if (!condition) {
        perror(operation);
        exit(1);
    }
}

static uint64_t clock_ns(void) {
    struct timespec now;
    require(!clock_gettime(CLOCK_MONOTONIC, &now), "clock_gettime");
    require(now.tv_sec >= 0 && now.tv_nsec >= 0 && now.tv_nsec < 1000000000, "clock value");
    return (uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec;
}

static void report(const char* stage, uint64_t before) {
    uint64_t after = clock_ns();
    require(after >= before, "clock monotonicity");
    printf("CLOCK_ELAPSED stage=%s before=%" PRIu64 " after=%" PRIu64 " elapsed_ns=%" PRIu64 "\n",
           stage, before, after, after - before);
}

static void sleep_ms(unsigned milliseconds) {
    struct timespec delay = {milliseconds / 1000, (milliseconds % 1000) * 1000000};
    while (nanosleep(&delay, NULL))
        require(errno == EINTR, "nanosleep");
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct timespec resolution;
    require(!clock_getres(CLOCK_MONOTONIC, &resolution) && !resolution.tv_sec &&
                resolution.tv_nsec == 10000000,
            "clock_getres");
    uint64_t before = clock_ns();
    sleep_ms(100);
    report("sleep-before", before);
    require(!mkdir("/mnt", 0755) && !mkdir("/mnt/clock", 0755), "mkdir");
    before = clock_ns();
    require(!mount("/dev/vda", "/mnt/clock", "ext2", 0, NULL), "mount");
    report("mount", before);
    int fd = open("/mnt/clock/elapsed", O_RDWR | O_CREAT | O_TRUNC, 0600);
    require(fd >= 0 && write(fd, "clock\n", 6) == 6, "write");

    int ready[2], done[2];
    require(!pipe(ready) && !pipe(done), "pipe");
    pid_t child = fork();
    require(child >= 0, "fork");
    if (!child) {
        close(ready[0]);
        close(done[0]);
        close(fd);
        struct timespec deadline;
        require(!clock_gettime(CLOCK_MONOTONIC, &deadline), "child deadline");
        deadline.tv_sec++;
        uint32_t word = 0;
        require(write(ready[1], "r", 1) == 1, "child ready");
        require(!sched_yield(), "child startup yield");
        long waited;
        do {
            waited = syscall(SYS_futex, &word, 9 | 128, 0, &deadline, NULL, UINT32_MAX);
        } while (waited < 0 && errno == EINTR);
        require(waited == -1 && errno == ETIMEDOUT, "child absolute futex timeout");
        require(write(done[1], "d", 1) == 1, "child wake");
        _exit(0);
    }
    close(ready[1]);
    close(done[1]);
    char byte;
    require(read(ready[0], &byte, 1) == 1 && byte == 'r', "child startup");
    struct sigaction action = {.sa_handler = alarm_handler};
    sigemptyset(&action.sa_mask);
    require(!sigaction(SIGALRM, &action, NULL), "sigaction");
    struct itimerval timer = {.it_value = {.tv_sec = 2}};
    require(!setitimer(ITIMER_REAL, &timer, NULL), "setitimer");
    before = clock_ns();
    require(!fsync(fd), "fsync");
    report("fsync", before);
    struct pollfd descriptor = {.fd = done[0], .events = POLLIN};
    int result;
    do {
        result = poll(&descriptor, 1, 200);
    } while (result < 0 && errno == EINTR);
    require(result >= 0, "poll");
    int child_ready =
        result == 1 && (descriptor.revents & POLLIN) && read(done[0], &byte, 1) == 1 && byte == 'd';
    printf("CLOCK_DEADLINE alarm=%d child_ready=%d\n", (int)alarm_seen, child_ready);
    timer = (struct itimerval){0};
    require(!setitimer(ITIMER_REAL, &timer, NULL), "timer clear");
    before = clock_ns();
    sleep_ms(100);
    report("sleep-after", before);
    struct timeval wall;
    require(!gettimeofday(&wall, NULL), "gettimeofday");
    uint64_t mono = clock_ns(),
             wall_ns = (uint64_t)wall.tv_sec * 1000000000 + (uint64_t)wall.tv_usec * 1000;
    require(mono >= wall_ns && mono - wall_ns <= 20000000, "boot-relative clock agreement");
    int status;
    while (waitpid(child, &status, 0) < 0)
        require(errno == EINTR, "waitpid");
    require(WIFEXITED(status) && !WEXITSTATUS(status), "child status");
    require(!close(fd), "close");
    close(ready[0]);
    close(done[0]);
    puts("CLOCK_ELAPSED_TESTS_PASS");
    return 0;
}

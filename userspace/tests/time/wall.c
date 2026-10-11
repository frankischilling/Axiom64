// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "CLOCK_WALL_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

static uint64_t monotonic_ns(void) {
    struct timespec value;
    require(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic time");
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

int main(void) {
    setbuf(stdout, NULL);
    struct timespec first, last, resolution;
    struct timeval wall;
    require(!clock_gettime(CLOCK_REALTIME, &first), "realtime time");
    require(!gettimeofday(&wall, NULL), "timeval time");
    int64_t seconds = -1;
    long returned = syscall(SYS_time, &seconds);
    require(returned == seconds && !clock_gettime(CLOCK_REALTIME, &last) &&
                seconds >= first.tv_sec && seconds <= last.tv_sec && wall.tv_sec >= first.tv_sec &&
                wall.tv_sec <= last.tv_sec && wall.tv_usec >= 0 && wall.tv_usec < 1000000,
            "wall interfaces agree");
    printf("CLOCK_WALL_OBSERVATION seconds=%" PRId64 " nanoseconds=%ld monotonic_ns=%" PRIu64 "\n",
           (int64_t)last.tv_sec, last.tv_nsec, monotonic_ns());
    require(!clock_getres(CLOCK_REALTIME, &resolution) && resolution.tv_sec == 0 &&
                resolution.tv_nsec > 0 && resolution.tv_nsec <= 10000000 &&
                !clock_getres(CLOCK_REALTIME, NULL),
            "supported realtime resolution");
    require(syscall(SYS_clock_gettime, CLOCK_REALTIME, 1) == -1 && errno == EFAULT &&
                syscall(SYS_gettimeofday, 1, 0) == -1 && errno == EFAULT &&
                syscall(SYS_time, 1) == -1 && errno == EFAULT,
            "wall copy faults");
    require(syscall(SYS_clock_gettime, 1001, &last) == -1 && errno == EINVAL &&
                syscall(SYS_clock_getres, 1001, &last) == -1 && errno == EINVAL,
            "invalid clock identifiers");
    struct timespec deadline;
    require(!clock_gettime(CLOCK_REALTIME, &deadline), "realtime deadline");
    deadline.tv_nsec += 200000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000;
    }
    uint32_t word = 0;
    uint64_t before = monotonic_ns();
    require(syscall(SYS_futex, &word, FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME, 0,
                    &deadline, NULL, UINT32_MAX) == -1 &&
                errno == ETIMEDOUT,
            "absolute realtime futex deadline");
    uint64_t elapsed = monotonic_ns() - before;
    require(elapsed >= 180000000 && elapsed <= 1500000000, "real monotonic deadline interval");
    deadline = (struct timespec){0};
    require(syscall(SYS_futex, &word, FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME, 0,
                    &deadline, NULL, UINT32_MAX) == -1 &&
                errno == ETIMEDOUT,
            "past realtime deadline");
    require(syscall(SYS_futex, &word, FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME, 1,
                    &deadline, NULL, UINT32_MAX) == -1 &&
                errno == EAGAIN,
            "futex value precedes expired deadline");
    printf("CLOCK_WALL_PASS elapsed_ns=%" PRIu64 " faults=3 clock_ids=2 past=checked\n", elapsed);
}

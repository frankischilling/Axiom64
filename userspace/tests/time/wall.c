// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/stat.h>
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

static int between(struct timespec value, struct timespec first, struct timespec last) {
    // Filesystem clocks can round down more coarsely than CLOCK_REALTIME.
    return value.tv_sec >= first.tv_sec - 1 && value.tv_sec <= last.tv_sec && value.tv_nsec >= 0 &&
           value.tv_nsec < 1000000000;
}

static void filesystem_time(void) {
    struct timespec first, last;
    struct stat metadata;
    char name[] = "/tmp/axiom64-clock-wall-XXXXXX";
    require(!clock_gettime(CLOCK_REALTIME, &first), "filesystem creation lower bound");
    int fd = mkstemp(name);
    require(fd >= 0 && !fstat(fd, &metadata) && !clock_gettime(CLOCK_REALTIME, &last),
            "filesystem creation observation");
    require(between(metadata.st_atim, first, last) && between(metadata.st_mtim, first, last) &&
                between(metadata.st_ctim, first, last),
            "filesystem creation uses calendar time");
    require(!clock_gettime(CLOCK_REALTIME, &first), "filesystem write lower bound");
    require(write(fd, "calendar", 8) == 8 && !fsync(fd) && !fstat(fd, &metadata) &&
                !clock_gettime(CLOCK_REALTIME, &last),
            "filesystem write observation");
    require(between(metadata.st_mtim, first, last) && between(metadata.st_ctim, first, last),
            "filesystem write uses calendar time");
    require(!unlink(name) && !close(fd), "filesystem calendar cleanup");
    puts("CLOCK_WALL_FILESYSTEM_PASS creation=3 write=2");
}

int main(void) {
    setbuf(stdout, NULL);
    filesystem_time();
    struct timespec first, last, coarse_first, coarse_last, resolution;
    struct timeval wall;
    require(!clock_gettime(CLOCK_REALTIME_COARSE, &coarse_first), "coarse realtime lower bound");
    require(!clock_gettime(CLOCK_REALTIME, &first), "realtime time");
    require(!gettimeofday(&wall, NULL), "timeval time");
    int64_t seconds = -1;
    long returned = syscall(SYS_time, &seconds);
    require(!clock_gettime(CLOCK_REALTIME, &last) &&
                !clock_gettime(CLOCK_REALTIME_COARSE, &coarse_last),
            "wall interface upper bounds");
    printf("CLOCK_WALL_INTERFACES precise_first_s=%" PRId64 " precise_first_ns=%ld"
           " timeval_s=%" PRId64 " timeval_us=%ld time_return_s=%ld time_store_s=%" PRId64
           " precise_last_s=%" PRId64 " precise_last_ns=%ld"
           " coarse_first_s=%" PRId64 " coarse_first_ns=%ld"
           " coarse_last_s=%" PRId64 " coarse_last_ns=%ld\n",
           (int64_t)first.tv_sec, first.tv_nsec, (int64_t)wall.tv_sec, (long)wall.tv_usec, returned,
           seconds, (int64_t)last.tv_sec, last.tv_nsec, (int64_t)coarse_first.tv_sec,
           coarse_first.tv_nsec, (int64_t)coarse_last.tv_sec, coarse_last.tv_nsec);
    // Linux time(2) uses cached seconds, which can trail precise realtime at
    // a second boundary. Observe each interface inside its actual clock bracket.
    require(returned == seconds && seconds >= coarse_first.tv_sec &&
                seconds <= coarse_last.tv_sec && wall.tv_sec >= first.tv_sec &&
                wall.tv_sec <= last.tv_sec && wall.tv_usec >= 0 && wall.tv_usec < 1000000 &&
                first.tv_nsec >= 0 && first.tv_nsec < 1000000000 && last.tv_nsec >= 0 &&
                last.tv_nsec < 1000000000 && coarse_first.tv_nsec >= 0 &&
                coarse_first.tv_nsec < 1000000000 && coarse_last.tv_nsec >= 0 &&
                coarse_last.tv_nsec < 1000000000 &&
                (coarse_first.tv_sec < coarse_last.tv_sec ||
                 (coarse_first.tv_sec == coarse_last.tv_sec &&
                  coarse_first.tv_nsec <= coarse_last.tv_nsec)),
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

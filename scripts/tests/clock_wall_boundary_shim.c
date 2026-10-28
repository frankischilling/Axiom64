// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>

int __real_puts(const char*);
int __real_clock_gettime(clockid_t, struct timespec*);
int __real_gettimeofday(struct timeval*, void*);
long __real_syscall(long, ...);

static int active, precise_reads, coarse_reads, time_reads;

static int mode(const char* name) {
    const char* selected = getenv("CLOCK_WALL_BOUNDARY_CASE");
    return selected && !strcmp(selected, name);
}

int __wrap_puts(const char* text) {
    if (!strcmp(text, "CLOCK_WALL_FILESYSTEM_PASS creation=3 write=2"))
        active = 1;
    return __real_puts(text);
}

int __wrap_clock_gettime(clockid_t clock, struct timespec* value) {
    if (active && clock == CLOCK_REALTIME && precise_reads < 2) {
        *value =
            (struct timespec){mode("same-second") ? 100 : 101, mode("same-second") ? 900000000 : 0};
        value->tv_nsec += precise_reads++ * 1000000;
        if (mode("bad-precise-fraction"))
            value->tv_nsec = 1000000000;
        return 0;
    }
    if (active && clock == CLOCK_REALTIME_COARSE && coarse_reads < 2) {
        *value = (struct timespec){100, 899000000};
        if (mode("coarse-crossing") && coarse_reads)
            *value = (struct timespec){101, 0};
        if (mode("bad-coarse-order") && !coarse_reads)
            value->tv_sec = 101;
        if (mode("bad-coarse-fraction"))
            value->tv_nsec = 1000000000;
        coarse_reads++;
        return 0;
    }
    return __real_clock_gettime(clock, value);
}

int __wrap_gettimeofday(struct timeval* value, void* zone) {
    if (active) {
        *value =
            (struct timeval){mode("same-second") ? 100 : 101, mode("same-second") ? 900001 : 1};
        if (mode("bad-timeval-low"))
            value->tv_sec = 99;
        if (mode("bad-timeval-high"))
            value->tv_sec = 102;
        if (mode("bad-timeval-fraction"))
            value->tv_usec = 1000000;
        return 0;
    }
    return __real_gettimeofday(value, zone);
}

long __wrap_syscall(long number, ...) {
    va_list arguments;
    va_start(arguments, number);
    long result;
    if (number == SYS_time) {
        int64_t* value = va_arg(arguments, int64_t*);
        if (active && !time_reads++) {
            *value = mode("bad-seconds-low") ? 99 : mode("bad-seconds-high") ? 102 : 100;
            result = *value + mode("bad-return");
        } else
            result = __real_syscall(number, value);
    } else if (number == SYS_clock_gettime || number == SYS_clock_getres) {
        int clock = va_arg(arguments, int);
        void* value = va_arg(arguments, void*);
        result = __real_syscall(number, clock, value);
    } else if (number == SYS_gettimeofday) {
        uintptr_t value = va_arg(arguments, uintptr_t);
        uintptr_t zone = va_arg(arguments, uintptr_t);
        result = __real_syscall(number, value, zone);
    } else if (number == SYS_futex) {
        uint32_t* address = va_arg(arguments, uint32_t*);
        int operation = va_arg(arguments, int);
        int value = va_arg(arguments, int);
        struct timespec* deadline = va_arg(arguments, struct timespec*);
        void* second_address = va_arg(arguments, void*);
        unsigned bitset = va_arg(arguments, unsigned);
        result =
            __real_syscall(number, address, operation, value, deadline, second_address, bitset);
    } else {
        abort();
    }
    va_end(arguments);
    return result;
}

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/timerfd.c
 * @brief   Timerfd userspace test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks timer programming, expiration counts, readiness, and blocking reads.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "TIMERFD_FAIL line=%d errno=%d condition=%s\n", __LINE__, errno,       \
                    #condition);                                                                   \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static const int64_t second = 1000000000;
static const unsigned long set_ticks = _IOW('T', 0, uint64_t);
static int guest;

static int64_t nanoseconds(struct timespec time) {
    return time.tv_sec * second + time.tv_nsec;
}

static int64_t now(clockid_t clock) {
    struct timespec value;
    CHECK(clock_gettime(clock, &value) == 0);
    return nanoseconds(value);
}

static void ticks(int fd, uint64_t value) {
    CHECK(ioctl(fd, set_ticks, &value) == 0);
}

static uint64_t take(int fd) {
    uint64_t value;
    CHECK(read(fd, &value, sizeof(value)) == sizeof(value));
    return value;
}

static void empty(int fd) {
    uint64_t value;
    CHECK(read(fd, &value, sizeof(value)) == -1 && errno == EAGAIN);
}

static void wait_for_expiration(int fd) {
    struct pollfd poller = {fd, POLLIN | POLLOUT, 0};
    CHECK(poll(&poller, 1, 2000) == 1 && poller.revents == POLLIN);
}

static void creation(void) {
    CHECK(timerfd_create(CLOCK_PROCESS_CPUTIME_ID, 0) == -1 && errno == EINVAL);
    CHECK(timerfd_create(CLOCK_MONOTONIC, 1) == -1 && errno == EINVAL);
    int wake = timerfd_create(CLOCK_BOOTTIME_ALARM, 0);
    if (wake >= 0)
        CHECK(!guest && !geteuid() && close(wake) == 0);
    else
        CHECK(errno == EPERM || (!guest && errno == EINVAL));
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    CHECK((fcntl(fd, F_GETFL) & (O_NONBLOCK | O_ACCMODE)) == (O_NONBLOCK | O_RDWR));
    struct stat metadata;
    CHECK(fstat(fd, &metadata) == 0 && metadata.st_mode == 0600);
    struct itimerspec value = {{0, 0}, {0, 0}};
    CHECK(timerfd_gettime(-1, &value) == -1 && errno == EBADF);
    CHECK(timerfd_gettime(STDOUT_FILENO, &value) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_timerfd_gettime, fd, 1) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_timerfd_settime, -1, 0, 1, 0) == -1 && errno == EFAULT);
    CHECK(timerfd_settime(-1, 4, &value, 0) == -1 && errno == EINVAL);
    CHECK(timerfd_settime(-1, 0, &value, 0) == -1 && errno == EBADF);
    value.it_interval.tv_nsec = second;
    CHECK(timerfd_settime(fd, 0, &value, 0) == -1 && errno == EINVAL);
    value.it_interval.tv_nsec = 0;
    value.it_value.tv_sec = -1;
    CHECK(timerfd_settime(fd, 0, &value, 0) == -1 && errno == EINVAL);
    value.it_value = (struct timespec){0, 1};
    CHECK(syscall(SYS_timerfd_settime, fd, TFD_TIMER_ABSTIME, &value, 1) == -1 && errno == EFAULT);
    wait_for_expiration(fd);
    CHECK(take(fd) == 1);
    CHECK(close(fd) == 0);

    struct rlimit limit, lowered;
    CHECK(getrlimit(RLIMIT_NOFILE, &limit) == 0);
    lowered = (struct rlimit){0, limit.rlim_max};
    CHECK(setrlimit(RLIMIT_NOFILE, &lowered) == 0);
    CHECK(timerfd_create(CLOCK_MONOTONIC, 0) == -1 && errno == EMFILE);
    CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    puts("TIMERFD_GROUP_PASS creation");
}

static void expiration(void) {
    const clockid_t clocks[] = {CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_REALTIME};
    for (size_t index = 0; index < sizeof(clocks) / sizeof(clocks[0]); index++) {
        int fd = timerfd_create(clocks[index], TFD_NONBLOCK);
        CHECK(fd >= 0);
        struct itimerspec setting = {{0, 0}, {0, 80000000}}, previous;
        int64_t start = now(CLOCK_MONOTONIC);
        CHECK(timerfd_settime(fd, 0, &setting, &previous) == 0);
        CHECK(!nanoseconds(previous.it_value) && !nanoseconds(previous.it_interval));
        wait_for_expiration(fd);
        CHECK(now(CLOCK_MONOTONIC) - start >= 60000000);
        CHECK(take(fd) == 1);
        empty(fd);
        CHECK(timerfd_gettime(fd, &previous) == 0 && !nanoseconds(previous.it_value));
        setting = (struct itimerspec){{0, 0}, {0, 1}};
        CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET, &setting, 0) == 0);
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(fd, &read_set);
        struct timeval timeout = {1, 0};
        CHECK(select(fd + 1, &read_set, 0, 0, &timeout) == 1 && FD_ISSET(fd, &read_set));
        CHECK(take(fd) == 1 && close(fd) == 0);
    }

    int fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
    CHECK(fd >= 0);
    const int64_t interval = second / 10;
    int64_t initial = now(CLOCK_REALTIME) - second;
    struct itimerspec setting = {{0, interval}, {initial / second, initial % second}};
    CHECK(timerfd_settime(fd, TFD_TIMER_ABSTIME, &setting, 0) == 0);
    wait_for_expiration(fd);
    int64_t before = now(CLOCK_REALTIME);
    uint64_t count = take(fd);
    int64_t after = now(CLOCK_REALTIME);
    CHECK(count >= (uint64_t)((before - initial) / interval + 1));
    CHECK(count <= (uint64_t)((after - initial) / interval + 1));
    setting = (struct itimerspec){{0, 0}, {0, 0}};
    struct itimerspec previous;
    CHECK(timerfd_settime(fd, 0, &setting, &previous) == 0);
    CHECK(nanoseconds(previous.it_interval) == interval);
    CHECK(nanoseconds(previous.it_value) > 0 && nanoseconds(previous.it_value) <= interval);
    empty(fd);
    CHECK(close(fd) == 0);
    puts("TIMERFD_GROUP_PASS expiration");
}

static void read_contract(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    CHECK(fd >= 0);
    uint64_t value = 0;
    unsigned char data[16];
    CHECK(read(fd, data, 7) == -1 && errno == EINVAL);
    CHECK(read(fd, data, 0) == -1 && errno == EINVAL);
    struct iovec vector[] = {{data, 0}};
    CHECK(readv(fd, vector, 1) == 0);
    CHECK(write(fd, &value, sizeof(value)) == -1 && errno == EINVAL);
    CHECK(writev(fd, vector, 1) == -1 && errno == EINVAL);
    CHECK(pread(fd, &value, sizeof(value), 0) == -1 && errno == ESPIPE);
    off_t seek = lseek(fd, 8, SEEK_SET);
    CHECK(seek == 0 || (!guest && seek == -1 && errno == ESPIPE));
    CHECK(ioctl(fd, set_ticks, &value) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_ioctl, fd, set_ticks, 1) == -1 && errno == EFAULT);
    CHECK(ioctl(fd, _IO('T', 1), 0) == -1 && errno == ENOTTY);
    ticks(fd, UINT64_C(0x1020304050607080));
    memset(data, 0x5a, sizeof(data));
    CHECK(read(fd, data, sizeof(data)) == 8 && data[8] == 0x5a);
    memcpy(&value, data, 8);
    CHECK(value == UINT64_C(0x1020304050607080));

    struct iovec split[] = {{data, 3}, {data + 3, 5}};
    ticks(fd, 29);
    ssize_t result = readv(fd, split, 2);
    int iter = result == 8;
    if (iter) {
        memcpy(&value, data, 8);
        CHECK(value == 29);
    } else {
        CHECK(!guest && result == -1 && errno == EINVAL && take(fd) == 29);
    }
    empty(fd);

    long page = sysconf(_SC_PAGESIZE);
    char* memory = mmap(0, page * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    CHECK(page > 0 && memory != MAP_FAILED && mprotect(memory + page, page, PROT_NONE) == 0);
    ticks(fd, 0x40);
    result = read(fd, memory + page - 4, 8);
    if (iter)
        CHECK(result == 4 && memory[page - 4] == 0x40);
    else
        CHECK(result == -1 && errno == EFAULT);
    empty(fd);
    CHECK(munmap(memory, page * 2) == 0 && close(fd) == 0);
    printf("TIMERFD_GROUP_PASS read-contract iter=%d seek=%ld\n", iter, (long)seek);
}

static void edges(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK), epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(fd >= 0 && epoll >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u64 = 0x54};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &event) == 0);
    ticks(fd, 11);
    CHECK(epoll_wait(epoll, &event, 1, 1000) == 1 && event.events == EPOLLIN &&
          event.data.u64 == 0x54);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    ticks(fd, 12);
    CHECK(epoll_wait(epoll, &event, 1, 1000) == 1 && take(fd) == 12);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);

    const struct itimerspec periodic = {{0, 250000000}, {0, 1}};
    CHECK(timerfd_settime(fd, 0, &periodic, 0) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 1000) == 1);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    struct itimerspec current;
    CHECK(timerfd_gettime(fd, &current) == 0 && nanoseconds(current.it_value) > 0);
    CHECK(epoll_wait(epoll, &event, 1, 2000) == 1 && take(fd) >= 2);
    CHECK(close(fd) == 0 && close(epoll) == 0);
    puts("TIMERFD_GROUP_PASS edge-readiness");
}

struct wait_read {
    int fd, error;
    atomic_int tid;
    ssize_t result;
    uint64_t count;
};

static void* read_timer(void* argument) {
    struct wait_read* wait = argument;
    atomic_store(&wait->tid, (int)syscall(SYS_gettid));
    wait->result = read(wait->fd, &wait->count, sizeof(wait->count));
    wait->error = errno;
    return 0;
}

static void wait_until_blocked(struct wait_read* wait) {
    for (int n = 0; n < 2000; n++) {
        int tid = atomic_load(&wait->tid);
        if (tid) {
            char path[48], text[2048];
            snprintf(path, sizeof(path), "/proc/%d/status", tid);
            int descriptor = open(path, O_RDONLY);
            CHECK(descriptor >= 0);
            ssize_t got = read(descriptor, text, sizeof(text) - 1);
            CHECK(got > 0 && close(descriptor) == 0);
            text[got] = 0;
            char state = 0;
            char* field = strstr(text, "\nState:");
            if (field && sscanf(field, "\nState: %c", &state) == 1 && state == 'S')
                return;
        }
        usleep(1000);
    }
    CHECK(0 && "timerfd read did not block");
}

static void signal_handler(int signal) {
    (void)signal;
}

static void lifetime(const char* program) {
    int fd = timerfd_create(CLOCK_MONOTONIC, 0), alias = dup(fd),
        replacement = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    CHECK(fd >= 0 && alias >= 0 && replacement >= 0);
    struct wait_read wait = {.fd = fd};
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, read_timer, &wait) == 0);
    wait_until_blocked(&wait);
    CHECK(dup2(replacement, fd) == fd);
    ticks(alias, 41);
    CHECK(pthread_join(thread, 0) == 0 && wait.result == 8 && wait.count == 41);
    empty(fd);
    CHECK(close(fd) == 0);

    struct sigaction action = {.sa_handler = signal_handler};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, 0) == 0);
    wait = (struct wait_read){.fd = alias};
    CHECK(pthread_create(&thread, 0, read_timer, &wait) == 0);
    wait_until_blocked(&wait);
    CHECK(pthread_kill(thread, SIGUSR1) == 0 && pthread_join(thread, 0) == 0);
    CHECK(wait.result == -1 && wait.error == EINTR);

    ticks(alias, 17);
    ticks(replacement, 19);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char inherited[20], closed[20];
        snprintf(inherited, sizeof(inherited), "%d", alias);
        snprintf(closed, sizeof(closed), "%d", replacement);
        execl(program, program, "--exec-child", inherited, closed, (char*)0);
        CHECK(0 && "timerfd exec failed");
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(take(alias) == 23 && take(replacement) == 19);
    CHECK(close(alias) == 0 && close(replacement) == 0);
    puts("TIMERFD_GROUP_PASS lifetime");
}

int main(int argc, char** argv) {
    if (argc == 4 && !strcmp(argv[1], "--exec-child")) {
        int fd = atoi(argv[2]);
        CHECK(fcntl(atoi(argv[3]), F_GETFD) == -1 && errno == EBADF);
        CHECK(take(fd) == 17);
        ticks(fd, 23);
        return 0;
    }
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")));
    if (argc == 2)
        CHECK(setgroups(0, 0) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    struct utsname system;
    CHECK(uname(&system) == 0);
    guest = !strcmp(system.sysname, "Axiom64");
    setvbuf(stdout, 0, _IONBF, 0);
    printf("TIMERFD_BEGIN uid=%u guest=%d\n", (unsigned)geteuid(), guest);
    creation();
    expiration();
    read_contract();
    edges();
    lifetime(argv[0]);
    puts("TIMERFD_PASS groups=5");
    return 0;
}

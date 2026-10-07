// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_LINKAGE
#define FUTEX_LINKAGE "static"
#endif
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "FUTEX_FAIL line=%d: %s errno=%d\n", __LINE__, #expr, errno); \
    exit(1); } } while (0)
enum { WAIT = 0, WAKE = 1, REQUEUE = 3, CMP_REQUEUE = 4,
       WAIT_BITSET = 9, WAKE_BITSET = 10, PRIVATE = 128 };
static long futex(uint32_t* word, int op, int value, const void* fourth,
                  uint32_t* second, uint32_t mask) {
    return syscall(SYS_futex, word, op, value, fourth, second, mask);
}
static atomic_uint entered;
static volatile sig_atomic_t signaled;
static void signal_handler(int signal) {
    if (signal == SIGUSR1)
        signaled++;
}
struct Waiter {
    uint32_t* word;
    int op, value, timed, error;
    uint32_t mask;
    struct timespec deadline;
};
static void* waiter(void* pointer) {
    struct Waiter* args = pointer;
    atomic_fetch_add(&entered, 1);
    long result = futex(args->word, args->op, args->value,
                        args->timed ? &args->deadline : 0, 0, args->mask);
    CHECK(args->error ? result == -1 && errno == args->error : result == 0);
    return 0;
}
static struct timespec later(long milliseconds) {
    struct timespec at;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &at) == 0);
    at.tv_nsec += milliseconds * 1000000;
    at.tv_sec += at.tv_nsec / 1000000000;
    at.tv_nsec %= 1000000000;
    return at;
}
static void await_waiters(unsigned count) {
    struct timespec limit = later(2000), now;
    while (atomic_load(&entered) != count) {
        sched_yield();
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK(now.tv_sec < limit.tv_sec ||
              (now.tv_sec == limit.tv_sec && now.tv_nsec < limit.tv_nsec));
    }
    usleep(20000);
}
static void expect_child(pid_t child, int expected) {
    int status;
    CHECK(waitpid(child, &status, 0) == child &&
          WIFEXITED(status) && WEXITSTATUS(status) == expected);
}
int main(void) {
    uint32_t words[2] = {44, 44};
    struct timespec immediate = {0, 0}, invalid = {0, 1000000000};
    CHECK(futex(words, WAIT | PRIVATE, 43, 0, 0, 0) == -1 && errno == EAGAIN);
    CHECK(futex(words, WAIT | PRIVATE, 44, &immediate, 0, 0) == -1 && errno == ETIMEDOUT);
    CHECK(futex(words, WAIT, 44, &invalid, 0, 0) == -1 && errno == EINVAL);
    CHECK(futex(words, WAKE | PRIVATE, -1, 0, 0, 0) == 0);
    CHECK(futex(words, WAKE_BITSET | PRIVATE, 1, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(futex((uint32_t*)((char*)words + 1), WAIT, 44, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(futex((uint32_t*)(uintptr_t)0x12345000, WAKE, 1, 0, 0, 0) == -1 && errno == EFAULT);
    CHECK(futex(words, 127, 0, 0, 0, 0) == -1 && errno == ENOSYS);
    pthread_t threads[3];
    struct Waiter args[3];
    atomic_store(&entered, 0);
    for (unsigned i = 0; i < 2; i++) {
        args[i] = (struct Waiter){.word=words, .op=WAIT_BITSET | PRIVATE, .value=44, .mask=1u<<i};
        CHECK(pthread_create(&threads[i], 0, waiter, &args[i]) == 0);
    }
    await_waiters(2);
    CHECK(futex(words, WAKE_BITSET | PRIVATE, 2, 0, 0, 4) == 0);
    CHECK(futex(words, WAKE_BITSET | PRIVATE, 2, 0, 0, 1) == 1);
    CHECK(futex(words, WAKE_BITSET | PRIVATE, 2, 0, 0, 2) == 1);
    for (unsigned i = 0; i < 2; i++)
        CHECK(pthread_join(threads[i], 0) == 0);
    atomic_store(&entered, 0);
    for (unsigned i = 0; i < 3; i++) {
        args[i] = (struct Waiter){.word=words, .op=WAIT | PRIVATE, .value=44};
        CHECK(pthread_create(&threads[i], 0, waiter, &args[i]) == 0);
    }
    await_waiters(3);
    CHECK(futex(words, CMP_REQUEUE | PRIVATE, 1, (void*)2, words + 1, 43) == -1 &&
          errno == EAGAIN);
    CHECK(futex(words, CMP_REQUEUE | PRIVATE, 1, (void*)2, words + 1, 44) == 3);
    CHECK(futex(words, WAKE | PRIVATE, INT_MAX, 0, 0, 0) == 0);
    CHECK(futex(words + 1, WAKE | PRIVATE, INT_MAX, 0, 0, 0) == 2);
    for (unsigned i = 0; i < 3; i++)
        CHECK(pthread_join(threads[i], 0) == 0);
    struct sigaction action = {.sa_handler=signal_handler};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, 0) == 0);
    atomic_store(&entered, 0);
    args[0] = (struct Waiter){.word=words, .op=WAIT | PRIVATE, .value=44, .error=EINTR};
    CHECK(pthread_create(threads, 0, waiter, args) == 0);
    await_waiters(1);
    CHECK(pthread_kill(threads[0], SIGUSR1) == 0);
    CHECK(pthread_join(threads[0], 0) == 0 && signaled == 1);
    puts("FUTEX_BITSET_REQUEUE_PASS");

    int fd = open("/tmp/futex-alias", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && ftruncate(fd, 4096) == 0);
    uint32_t* first = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    uint32_t* second = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(first != MAP_FAILED && second != MAP_FAILED && first != second);
    *first = 44;
    atomic_store(&entered, 0);
    args[0] = (struct Waiter){.word=first, .op=WAIT, .value=44};
    CHECK(pthread_create(threads, 0, waiter, args) == 0);
    await_waiters(1);
    CHECK(munmap(first, 4096) == 0);
    CHECK(futex(second, WAKE | PRIVATE, 1, 0, 0, 0) == 0);
    CHECK(futex(second, WAKE, 1, 0, 0, 0) == 1);
    CHECK(pthread_join(threads[0], 0) == 0);
    CHECK(munmap(second, 4096) == 0 && close(fd) == 0 && unlink("/tmp/futex-alias") == 0);
    first = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(first != MAP_FAILED);
    *first = 44;
    atomic_store(&entered, 0);
    args[0] = (struct Waiter){.word=first, .op=WAIT_BITSET, .value=44,
                             .timed=1, .error=ETIMEDOUT, .mask=UINT32_MAX,
                             .deadline=later(300)};
    CHECK(pthread_create(threads, 0, waiter, args) == 0);
    await_waiters(1);
    CHECK(munmap(first, 4096) == 0);
    second = mmap(first, 4096, PROT_READ | PROT_WRITE,
                  MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(second == first);
    *second = 44;
    CHECK(futex(second, WAKE, 1, 0, 0, 0) == 0);
    CHECK(pthread_join(threads[0], 0) == 0 && munmap(second, 4096) == 0);
    puts("FUTEX_MAPPING_LIFETIME_PASS");

    uint32_t* shared = mmap(0, 4096, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED);
    atomic_store((_Atomic uint32_t*)shared, 0);
    pid_t child = fork();
    CHECK(child >= 0);
    struct timespec limit = {2, 0};
    if (!child) {
        atomic_store((_Atomic uint32_t*)shared, 1);
        CHECK(futex(shared, WAKE, 1, 0, 0, 0) >= 0);
        while (atomic_load((_Atomic uint32_t*)shared) != 2)
            CHECK(futex(shared, WAIT, 1, &limit, 0, 0) == 0 || errno == EAGAIN);
        _exit(23);
    }
    while (!atomic_load((_Atomic uint32_t*)shared))
        CHECK(futex(shared, WAIT, 0, &limit, 0, 0) == 0 || errno == EAGAIN);
    atomic_store((_Atomic uint32_t*)shared, 2);
    CHECK(futex(shared, WAKE, 1, 0, 0, 0) >= 0);
    expect_child(child, 23);
    CHECK(munmap(shared, 4096) == 0);
    printf("FUTEX_TESTS_PASS linkage=%s\n", FUTEX_LINKAGE);
    return 0;
}

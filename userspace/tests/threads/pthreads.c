// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <fenv.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef THREAD_LINKAGE
#define THREAD_LINKAGE "static"
#endif
#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "THREAD_FAIL line=%d: %s errno=%d\n", __LINE__, #expr, errno);         \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static _Thread_local unsigned local = 0x1234;
static pid_t process;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned items, produced, consumed, sum, ready;
static int shared_fd;
static atomic_uint detached;
static sem_t semaphore;

static void* identity(void* argument) {
    unsigned index = (uintptr_t)argument;
    CHECK(getpid() == process && syscall(SYS_gettid) != process);
    struct rlimit limit;
    CHECK(syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, 0, &limit) == 0 && limit.rlim_cur >= 12);
    CHECK(syscall(SYS_prlimit64, syscall(SYS_gettid), RLIMIT_NOFILE, 0, &limit) == 0);
    CHECK(local == 0x1234);
    local = index + 100;
    int rounding = index & 1 ? FE_DOWNWARD : FE_UPWARD;
    CHECK(fesetround(rounding) == 0);
    for (unsigned i = 0; i < 15; i++) {
        CHECK(local == index + 100 && fegetround() == rounding);
        sched_yield();
    }
    return (void*)(uintptr_t)(index + 900);
}
static void* resources(void* argument) {
    (void)argument;
    CHECK(chdir("/tmp/thread-directory") == 0);
    CHECK(umask(0077) == 0022);
    CHECK(close(shared_fd) == 0);
    shared_fd = open("shared-file", O_CREAT | O_RDWR | O_EXCL, 0666);
    CHECK(shared_fd >= 0 && write(shared_fd, "shared", 6) == 6);
    return 0;
}
static void* producer(void* argument) {
    unsigned base = (uintptr_t)argument;
    for (unsigned i = 0; i < 600; i++) {
        CHECK(pthread_mutex_lock(&mutex) == 0);
        while (items == 16)
            CHECK(pthread_cond_wait(&changed, &mutex) == 0);
        items++;
        produced++;
        sum += base + i;
        CHECK(pthread_cond_broadcast(&changed) == 0);
        CHECK(pthread_mutex_unlock(&mutex) == 0);
    }
    return 0;
}
static void* consumer(void* argument) {
    (void)argument;
    for (unsigned i = 0; i < 600; i++) {
        CHECK(pthread_mutex_lock(&mutex) == 0);
        while (!items)
            CHECK(pthread_cond_wait(&changed, &mutex) == 0);
        items--;
        consumed++;
        CHECK(pthread_cond_broadcast(&changed) == 0);
        CHECK(pthread_mutex_unlock(&mutex) == 0);
    }
    return 0;
}
static void* detached_worker(void* argument) {
    (void)argument;
    atomic_fetch_add(&detached, 1);
    return 0;
}
static void* sem_worker(void* argument) {
    (void)argument;
    CHECK(sem_wait(&semaphore) == 0);
    CHECK(pthread_mutex_lock(&mutex) == 0);
    ready++;
    CHECK(pthread_mutex_unlock(&mutex) == 0);
    return 0;
}
static struct timespec after_ms(long milliseconds) {
    struct timespec at;
    CHECK(clock_gettime(CLOCK_REALTIME, &at) == 0);
    at.tv_nsec += milliseconds * 1000000;
    at.tv_sec += at.tv_nsec / 1000000000;
    at.tv_nsec %= 1000000000;
    return at;
}
int main(int argc, char** argv) {
    process = getpid();
    CHECK(syscall(SYS_gettid) == process);
    pthread_t threads[12];
    int condition_only = argc == 2 && !strcmp(argv[1], "cond");
    if (condition_only)
        goto cond_tests;
    for (unsigned i = 0; i < 12; i++)
        CHECK(pthread_create(&threads[i], 0, identity, (void*)(uintptr_t)i) == 0);
    for (unsigned i = 0; i < 12; i++) {
        void* result;
        CHECK(pthread_join(threads[i], &result) == 0 && result == (void*)(uintptr_t)(i + 900));
    }
    CHECK(local == 0x1234 && fegetround() == FE_TONEAREST);
    puts("THREAD_TLS_FPU_PASS");
    CHECK(mkdir("/tmp/thread-directory", 0700) == 0);
    shared_fd = open("/dev/null", O_RDONLY);
    int closed = shared_fd;
    CHECK(pthread_create(&threads[0], 0, resources, 0) == 0);
    CHECK(pthread_join(threads[0], 0) == 0);
    char buffer[1024];
    CHECK(getcwd(buffer, sizeof(buffer)) && !strcmp(buffer, "/tmp/thread-directory"));
    CHECK(umask(0022) == 0077);
    CHECK(lseek(shared_fd, 0, SEEK_SET) == 0 && read(shared_fd, buffer, 6) == 6);
    CHECK(!memcmp(buffer, "shared", 6));
    if (closed != shared_fd)
        CHECK(fcntl(closed, F_GETFD) == -1 && errno == EBADF);
    struct stat st;
    CHECK(fstat(shared_fd, &st) == 0 && (st.st_mode & 0777) == 0600);
    CHECK(close(shared_fd) == 0 && unlink("shared-file") == 0 && chdir("/") == 0);
    CHECK(rmdir("/tmp/thread-directory") == 0);
    puts("THREAD_RESOURCES_PASS");
cond_tests:
    for (unsigned i = 0; i < 2; i++) {
        CHECK(pthread_create(&threads[i], 0, producer, (void*)(uintptr_t)(i * 1000)) == 0);
        CHECK(pthread_create(&threads[i + 2], 0, consumer, 0) == 0);
    }
    for (unsigned i = 0; i < 4; i++)
        CHECK(pthread_join(threads[i], 0) == 0);
    CHECK(produced == 1200 && consumed == 1200 && items == 0 && sum == 959400);
    CHECK(pthread_mutex_lock(&mutex) == 0);
    struct timespec at = after_ms(30);
    CHECK(pthread_cond_timedwait(&changed, &mutex, &at) == ETIMEDOUT);
    CHECK(pthread_mutex_unlock(&mutex) == 0);
    puts("THREAD_MUTEX_COND_PASS");
    if (condition_only)
        return 0;
    CHECK(sem_init(&semaphore, 0, 0) == 0);
    CHECK(pthread_create(&threads[0], 0, sem_worker, 0) == 0);
    usleep(20000);
    CHECK(ready == 0 && sem_post(&semaphore) == 0);
    CHECK(pthread_join(threads[0], 0) == 0 && ready == 1);
    at = after_ms(20);
    CHECK(sem_timedwait(&semaphore, &at) == -1 && errno == ETIMEDOUT);
    CHECK(sem_destroy(&semaphore) == 0);
    for (unsigned i = 0; i < 160; i++) {
        CHECK(pthread_create(&threads[0], 0, identity, (void*)(uintptr_t)i) == 0);
        CHECK(pthread_join(threads[0], 0) == 0);
    }
    pthread_attr_t attr;
    CHECK(pthread_attr_init(&attr) == 0);
    CHECK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0);
    for (unsigned i = 0; i < 160; i++) {
        CHECK(pthread_create(&threads[0], &attr, detached_worker, 0) == 0);
        while (atomic_load(&detached) <= i)
            sched_yield();
    }
    CHECK(pthread_attr_destroy(&attr) == 0);
    CHECK(pthread_mutex_destroy(&mutex) == 0 && pthread_cond_destroy(&changed) == 0);
    printf("THREAD_TESTS_PASS linkage=%s\n", THREAD_LINKAGE);
    return 0;
}

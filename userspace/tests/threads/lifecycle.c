// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LIFE_LINKAGE
#define LIFE_LINKAGE "static"
#endif
#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "LIFECYCLE_FAIL line=%d: %s errno=%d\n", __LINE__, #expr, errno); \
    exit(1); } } while (0)
static _Atomic int* relay;
static _Atomic int blocked_word;
static const char* helper = "/bin/abi-static";
static void wait_word(_Atomic int* word, int expected) {
    struct timespec limit = {2, 0};
    CHECK(syscall(SYS_futex, word, 0, expected, &limit, 0, 0) == 0 ||
          errno == EAGAIN || errno == EINTR);
}
static void wake_word(_Atomic int* word) {
    CHECK(syscall(SYS_futex, word, 1, 64, 0, 0, 0) >= 0);
}
static void child_status(pid_t child, int expected) {
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected)
        fprintf(stderr, "LIFECYCLE_STATUS child=%d got=%x expected=%d\n", child, status, expected);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}
static void* blocked(void* unused) {
    (void)unused;
    for (;;)
        wait_word(&blocked_word, 0);
    return 0;
}
static void* group_exit(void* unused) {
    (void)unused;
    usleep(30000);
    syscall(SYS_exit_group, 42);
    return 0;
}
static void* survive_leader(void* unused) {
    (void)unused;
    while (atomic_load(relay + 2))
        wait_word(relay + 2, atomic_load(relay + 2));
    atomic_store(relay, 1);
    wake_word(relay);
    while (!atomic_load(relay + 1))
        wait_word(relay + 1, 0);
    syscall(SYS_exit, 0);
    return 0;
}
static void* exec_worker(void* unused) {
    (void)unused;
    execl(helper, "abi-static", "child", (char*)0);
    _exit(99);
}
static void* fork_worker(void* unused) {
    (void)unused;
    pid_t group = getpid();
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(getpid() == syscall(SYS_gettid) && getppid() == group);
        execl(helper, "abi-static", "child", (char*)0);
        _exit(99);
    }
    child_status(child, 17);
    return (void*)(uintptr_t)91;
}
struct CloneArgs {
    _Atomic int parent_tid, child_tid, seen;
    int fd;
};
extern long test_clone(int (*fn)(void*), void* stack, unsigned long flags,
                       void* arg, void* parent_tid, void* child_tid);
static int clone_worker(void* pointer) {
    struct CloneArgs* args = pointer;
    CHECK(getpid() == syscall(SYS_gettid) && getpid() == atomic_load(&args->child_tid));
    CHECK(chdir("/tmp/clone-directory") == 0);
    CHECK(close(args->fd) == 0);
    atomic_store(&args->seen, getpid());
    return 31;
}
int main(int argc, char** argv) {
    if (argc == 2)
        helper = argv[1];
    pthread_t thread[4];
    for (unsigned cycle = 0; cycle < 12; cycle++) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            for (unsigned i = 0; i < 3; i++)
                CHECK(pthread_create(thread + i, 0, blocked, 0) == 0);
            CHECK(pthread_create(thread + 3, 0, group_exit, 0) == 0);
            for (;;)
                pause();
        }
        child_status(child, 42);
    }
    relay = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(relay != MAP_FAILED);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        atomic_store(relay + 2, getpid());
        CHECK(syscall(SYS_set_tid_address, relay + 2) == getpid());
        CHECK(pthread_create(thread, 0, survive_leader, 0) == 0);
        syscall(SYS_exit, 23);
        _exit(99);
    }
    while (!atomic_load(relay))
        wait_word(relay, 0);
    int status;
    CHECK(waitpid(child, &status, WNOHANG) == 0);
    CHECK(kill(child, SIGSTOP) == 0);
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    CHECK(kill(child, SIGCONT) == 0);
    CHECK(waitpid(child, &status, WCONTINUED) == child && WIFCONTINUED(status));
    atomic_store(relay + 1, 1);
    wake_word(relay + 1);
    child_status(child, 0);
    CHECK(munmap(relay, 4096) == 0);
    puts("THREAD_GROUP_LIFETIME_PASS");
    for (unsigned cycle = 0; cycle < 12; cycle++) {
        child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(pthread_create(thread, 0, blocked, 0) == 0);
            CHECK(pthread_create(thread + 1, 0, exec_worker, 0) == 0);
            for (;;)
                pause();
        }
        child_status(child, 17);
        child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(pthread_create(thread, 0, fork_worker, 0) == 0);
            void* result;
            CHECK(pthread_join(thread[0], &result) == 0 && result == (void*)(uintptr_t)91);
            _exit(29);
        }
        child_status(child, 29);
    }
    puts("THREAD_FORK_EXEC_PASS");
    CHECK(mkdir("/tmp/clone-directory", 0700) == 0);
    struct CloneArgs args = {0};
    args.fd = open("/dev/null", O_RDONLY);
    CHECK(args.fd >= 0);
    void* stack = mmap(0, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED);
    int flags = SIGCHLD | CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    /* Exercise the kernel flags independently of the libc clone wrapper. */
    long clone_result = test_clone(clone_worker, (char*)stack + 65536, flags, &args,
                                  &args.parent_tid, &args.child_tid);
    if (clone_result < 0)
        errno = -clone_result;
    child = clone_result;
    CHECK(child > 0 && atomic_load(&args.parent_tid) == child);
    while (atomic_load(&args.child_tid))
        wait_word(&args.child_tid, child);
    child_status(child, 31);
    CHECK(atomic_load(&args.seen) == child && !atomic_load(&args.child_tid));
    CHECK(fcntl(args.fd, F_GETFD) == -1 && errno == EBADF);
    char cwd[256];
    CHECK(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, "/tmp/clone-directory"));
    CHECK(chdir("/") == 0 && rmdir("/tmp/clone-directory") == 0 && munmap(stack, 65536) == 0);
    CHECK(syscall(SYS_clone, CLONE_THREAD | CLONE_VM, 0, 0, 0, 0) == -1 && errno == EINVAL);
    printf("THREAD_LIFECYCLE_PASS linkage=%s\n", LIFE_LINKAGE);
    return 0;
}

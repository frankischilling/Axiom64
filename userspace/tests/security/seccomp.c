// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/security/seccomp.c
 * @brief   Exercise Linux seccomp policy in native and Axiom64 guests.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define LENGTH(array) (sizeof(array) / sizeof((array)[0]))
#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "SECCOMP_FAIL line=%d check=%s errno=%d\n", __LINE__, #condition,      \
                    errno);                                                                        \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static long set_filter(struct sock_filter* instructions, unsigned count, unsigned flags) {
    struct sock_fprog program = {(unsigned short)count, instructions};
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &program);
}

static long filter_call(unsigned number, unsigned action, unsigned flags) {
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    return set_filter(instructions, LENGTH(instructions), flags);
}

static void no_new_privileges(void) {
    CHECK(!prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL));
}

static void check_denied(unsigned number, int expected) {
    errno = 0;
    CHECK(syscall(number, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL) == -1 && errno == expected);
}

static int status_value(const char* name) {
    char line[256];
    FILE* status = fopen("/proc/self/status", "r");
    CHECK(status);
    int value = -1;
    size_t length = strlen(name);
    while (fgets(line, sizeof(line), status))
        if (!strncmp(line, name, length) && line[length] == ':') {
            CHECK(sscanf(line + length + 1, "%d", &value) == 1);
            break;
        }
    CHECK(!fclose(status));
    return value;
}

static void check_validation(void) {
    unsigned action = SECCOMP_RET_TRAP;
    struct sock_filter accept[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_filter bad[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0), accept[0]};
    CHECK(!syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action));
    action = SECCOMP_RET_ALLOW | 1;
    CHECK(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &action) == -1 && errno == EOPNOTSUPP);
    CHECK(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, NULL) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 1, &action) == -1 && errno == EINVAL);
    CHECK(!prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL));
    CHECK(set_filter(accept, LENGTH(accept), 0) == -1 && errno == EACCES);
    no_new_privileges();
    CHECK(set_filter(accept, LENGTH(accept), 0x80000000u) == -1 && errno == EINVAL);
    CHECK(set_filter(accept, 0, 0) == -1 && errno == EINVAL);
    CHECK(set_filter(accept, 4097, 0) == -1 && errno == EINVAL);
    CHECK(set_filter(NULL, LENGTH(accept), 0) == -1 && errno == EINVAL);
    CHECK(set_filter((struct sock_filter*)1, LENGTH(accept), 0) == -1 && errno == EFAULT);
    bad[0].k = 2;
    CHECK(set_filter(bad, LENGTH(bad), 0) == -1 && errno == EINVAL);
    bad[0].k = sizeof(struct seccomp_data);
    CHECK(set_filter(bad, LENGTH(bad), 0) == -1 && errno == EINVAL);
    bad[0].code = BPF_LD | BPF_B | BPF_ABS;
    bad[0].k = 0;
    CHECK(set_filter(bad, LENGTH(bad), 0) == -1 && errno == EINVAL);
    bad[0].code = BPF_JMP | BPF_JA;
    bad[0].k = 9;
    CHECK(set_filter(bad, LENGTH(bad), 0) == -1 && errno == EINVAL);
    bad[0].code = BPF_LD | BPF_MEM;
    bad[0].k = 0;
    CHECK(set_filter(bad, LENGTH(bad), 0) == -1 && errno == EINVAL);
    bad[0].code = BPF_ALU | BPF_MOD | BPF_K;
    bad[0].k = 1;
    CHECK(set_filter(bad, LENGTH(bad), 0) == -1 && errno == EINVAL);
    CHECK(!prctl(PR_GET_SECCOMP, 0UL, 0UL, 0UL, 0UL));
}

static void check_arguments(void) {
    int descriptors[2];
    CHECK(!pipe2(descriptors, O_NONBLOCK));
    no_new_privileges();
    struct sock_filter policy[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)descriptors[1], 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {LENGTH(policy), policy};
    CHECK(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program, 0UL, 0UL));
    *(volatile uint32_t*)&policy[7].k = SECCOMP_RET_ALLOW;
    CHECK(prctl(PR_GET_SECCOMP, 0UL, 0UL, 0UL, 0UL) == 2);
    CHECK(status_value("Seccomp") == 2 && status_value("Seccomp_filters") == 1);
    CHECK(write(descriptors[1], "x", 1) == -1 && errno == EPERM);
    char byte;
    CHECK(read(descriptors[0], &byte, 1) == -1 && errno == EAGAIN);
    struct sock_filter upper[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[5]) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x12345678u, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ERANGE),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    CHECK(!set_filter(upper, LENGTH(upper), 0));
    CHECK(syscall(SYS_getppid, 0UL, 0UL, 0UL, 0UL, 0UL, 0x12345678UL << 32) == -1 &&
          errno == ERANGE);
    CHECK(syscall(SYS_getppid, 0UL, 0UL, 0UL, 0UL, 0UL, 0x12345678UL) > 0);
}

static void check_inheritance(void) {
    no_new_privileges();
    CHECK(!filter_call(SYS_getppid, SECCOMP_RET_ERRNO | EACCES, 0));
    CHECK(!filter_call(SYS_getppid, SECCOMP_RET_ALLOW, 0));
    check_denied(SYS_getppid, EACCES);
    CHECK(!filter_call(SYS_getppid, SECCOMP_RET_ERRNO | ESRCH, 0));
    check_denied(SYS_getppid, ESRCH);
    CHECK(!filter_call(SYS_getpid, SECCOMP_RET_ERRNO | 65535, 0));
    check_denied(SYS_getpid, 4095);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(status_value("Seccomp_filters") == 4);
        check_denied(SYS_getppid, ESRCH);
        execl("/proc/self/exe", "seccomp-child", "exec", (char*)NULL);
        CHECK(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
}

static atomic_int worker_tid, worker_go;

static void* sync_worker(void* context) {
    const int divergent = *(int*)context;
    if (divergent)
        CHECK(!filter_call(SYS_getppid, SECCOMP_RET_ERRNO | EACCES, 0));
    atomic_store(&worker_tid, (int)syscall(SYS_gettid));
    while (!atomic_load(&worker_go))
        sched_yield();
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL) == 1);
    check_denied(SYS_getppid, divergent ? EACCES : EPERM);
    return NULL;
}

static void check_sync(int divergent) {
    if (divergent)
        no_new_privileges();
    pthread_t thread;
    CHECK(!pthread_create(&thread, NULL, sync_worker, &divergent));
    while (!atomic_load(&worker_tid))
        sched_yield();
    no_new_privileges();
    if (divergent) {
        CHECK(filter_call(SYS_getppid, SECCOMP_RET_ERRNO | EPERM, SECCOMP_FILTER_FLAG_TSYNC) ==
              atomic_load(&worker_tid));
        CHECK(filter_call(SYS_getppid, SECCOMP_RET_ERRNO | EPERM,
                          SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_TSYNC_ESRCH) == -1 &&
              errno == ESRCH);
        CHECK(syscall(SYS_getppid) > 0);
    } else {
        CHECK(!filter_call(SYS_getppid, SECCOMP_RET_ALLOW, 0));
        CHECK(!filter_call(SYS_getppid, SECCOMP_RET_ERRNO | EPERM, SECCOMP_FILTER_FLAG_TSYNC));
        check_denied(SYS_getppid, EPERM);
    }
    atomic_store(&worker_go, 1);
    CHECK(!pthread_join(thread, NULL));
}

static void synchronized(void) {
    check_sync(0);
}

static void divergent(void) {
    check_sync(1);
}

static void check_path_limit(void) {
    no_new_privileges();
    static struct sock_filter program[4096];
    for (unsigned i = 0; i + 1 < LENGTH(program); ++i)
        program[i] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_IMM, SECCOMP_RET_ALLOW);
    program[LENGTH(program) - 1] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_A, 0);
    for (unsigned i = 0; i < 7; ++i)
        CHECK(!set_filter(program, LENGTH(program), 0));
    CHECK(set_filter(program, LENGTH(program), 0) == -1 && errno == ENOMEM);
    CHECK(status_value("Seccomp_filters") == 7);
}

static volatile sig_atomic_t trap_seen;

static void trap_handler(int signal, siginfo_t* info, void* context) {
    ucontext_t* frame = context;
    trap_seen = signal == SIGSYS && info->si_code == 1 && info->si_errno == 0x1234 &&
                info->si_syscall == SYS_getppid && info->si_arch == AUDIT_ARCH_X86_64 &&
                (uintptr_t)info->si_call_addr == (uintptr_t)frame->uc_mcontext.gregs[REG_RIP];
    frame->uc_mcontext.gregs[REG_RAX] = 12345;
}

static void check_trap(void) {
    struct sigaction handler = {.sa_sigaction = trap_handler, .sa_flags = SA_SIGINFO};
    CHECK(!sigemptyset(&handler.sa_mask) && !sigaction(SIGSYS, &handler, NULL));
    no_new_privileges();
    CHECK(!filter_call(SYS_getppid, SECCOMP_RET_TRAP | 0x1234, 0));
    CHECK(syscall(SYS_getppid) == 12345 && trap_seen);
}

static void strict_kill(void) {
    CHECK(!syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL));
    syscall(SYS_getppid);
    CHECK(0);
}

static void prctl_strict_kill(void) {
    CHECK(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 1UL, 0UL, 0UL));
    syscall(SYS_getppid);
    CHECK(0);
}

static void filter_kill(void) {
    no_new_privileges();
    CHECK(!filter_call(SYS_getppid, SECCOMP_RET_KILL_PROCESS, 0));
    CHECK(!filter_call(SYS_getppid, SECCOMP_RET_ALLOW, 0));
    syscall(SYS_getppid);
    CHECK(0);
}

static void* killed_worker(void* unused) {
    (void)unused;
    CHECK(syscall(SYS_set_tid_address, &worker_tid) > 0);
    CHECK(!filter_call(SYS_getppid, SECCOMP_RET_KILL_THREAD, 0));
    syscall(SYS_getppid);
    CHECK(0);
    return NULL;
}

static void thread_kill(void) {
    no_new_privileges();
    atomic_store(&worker_tid, 1);
    pthread_t thread;
    CHECK(!pthread_create(&thread, NULL, killed_worker, NULL));
    // Raw thread termination clears the kernel TID address without running pthread_exit.
    for (int i = 0; i < 5000 && atomic_load(&worker_tid); ++i)
        usleep(1000);
    CHECK(!atomic_load(&worker_tid));
    CHECK(syscall(SYS_getppid) > 0);
}

static void check_log_and_trace(void) {
    no_new_privileges();
    CHECK(!filter_call(SYS_getpid, SECCOMP_RET_LOG, 0));
    CHECK(syscall(SYS_getpid) > 0);
    CHECK(!filter_call(SYS_getppid, SECCOMP_RET_TRACE, 0));
    check_denied(SYS_getppid, ENOSYS);
}

static void run(const char* title, void (*test)(void), int expected_signal) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        test();
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(expected_signal ? WIFSIGNALED(status) && WTERMSIG(status) == expected_signal
                          : WIFEXITED(status) && !WEXITSTATUS(status));
    printf("SECCOMP_PASS %s\n", title);
    CHECK(!fflush(stdout));
}

int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "exec")) {
        CHECK(geteuid() == 1000 && status_value("NoNewPrivs") == 1 &&
              status_value("Seccomp_filters") == 4);
        check_denied(SYS_getppid, ESRCH);
        return 0;
    }
    if (!geteuid()) {
        CHECK(!setresgid(1000, 1000, 1000));
        CHECK(!setresuid(1000, 1000, 1000));
    }
    CHECK(geteuid() == 1000);
    run("validation", check_validation, 0);
    run("arguments", check_arguments, 0);
    run("stacking-and-inheritance", check_inheritance, 0);
    run("thread-sync", synchronized, 0);
    run("thread-sync-divergence", divergent, 0);
    run("instruction-budget", check_path_limit, 0);
    run("sigsys-info", check_trap, 0);
    run("strict-mode", strict_kill, SIGKILL);
    run("prctl-strict-mode", prctl_strict_kill, SIGKILL);
    run("kill-thread", thread_kill, 0);
    run("kill-process", filter_kill, SIGSYS);
    run("log-and-trace", check_log_and_trace, 0);
    puts("SECCOMP_TEST_PASS");
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "SIGWAIT_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,      \
                    #expression);                                                                  \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static volatile sig_atomic_t caught;
static const struct timespec zero = {0, 0};

static uint64_t bit(int number) {
    return 1ull << (number - 1);
}

static void record(const char* name) {
    printf("SIGWAIT_OBSERVATION case=%s\n", name);
    fflush(stdout);
    observations++;
}

static long waiting(uint64_t mask, siginfo_t* info, const struct timespec* timeout) {
    return syscall(SYS_rt_sigtimedwait, &mask, info, timeout, 8);
}

static void reaped(pid_t child) {
    int status;
    CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0);
}

static void pause_short(void) {
    struct timespec interval = {0, 50000000};
    while (nanosleep(&interval, &interval) < 0)
        CHECK(errno == EINTR);
}

static void handler(int number) {
    caught = number;
}

static pid_t sender(int number) {
    pid_t parent = getpid(), child = fork();
    CHECK(child >= 0);
    if (!child) {
        pause_short();
        CHECK(kill(parent, number) == 0);
        _exit(0);
    }
    return child;
}

static uint64_t milliseconds(void) {
    struct timespec value;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}

static int run_tests(void) {
    alarm(20);
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    sigaddset(&blocked, SIGUSR2);
    sigaddset(&blocked, SIGSYS);
    CHECK(sigprocmask(SIG_BLOCK, &blocked, NULL) == 0);
    uint64_t mask = bit(SIGUSR1);
    CHECK(syscall(SYS_rt_sigtimedwait, (void*)1, (void*)1, (void*)1, 7) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_rt_sigtimedwait, (void*)1, NULL, &zero, 8) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_rt_sigtimedwait, &mask, NULL, (void*)1, 8) == -1 && errno == EFAULT);
    CHECK(waiting(0, NULL, &zero) == -1 && errno == EAGAIN);
    CHECK(waiting(bit(SIGKILL) | bit(SIGSTOP), NULL, &zero) == -1 && errno == EAGAIN);
    record("arguments_and_unwaitable_signals");

    CHECK(kill(getpid(), SIGUSR1) == 0);
    struct timespec invalid[] = {{-1, 0}, {0, -1}, {0, 1000000000}, {1, LONG_MAX}};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++)
        CHECK(waiting(mask, NULL, &invalid[i]) == -1 && errno == EINVAL);
    CHECK(waiting(mask, NULL, &zero) == SIGUSR1);
    record("timeout_validation_preserves_pending");

    CHECK(kill(getpid(), SIGUSR1) == 0);
    CHECK(waiting(mask, (void*)1, &zero) == -1 && errno == EFAULT);
    CHECK(waiting(mask, NULL, &zero) == -1 && errno == EAGAIN);
    record("bad_output_consumes_signal");

    siginfo_t info;
    CHECK(kill(getpid(), SIGUSR1) == 0);
    memset(&info, 0xff, sizeof(info));
    CHECK(waiting(mask, &info, &zero) == SIGUSR1 && info.si_signo == SIGUSR1 &&
          info.si_code == SI_USER && info.si_pid == getpid() && info.si_uid == getuid() &&
          !info.si_errno);
    record("queued_sender_information");

    CHECK(kill(getpid(), SIGUSR1) == 0 && kill(getpid(), SIGSYS) == 0);
    CHECK(waiting(mask | bit(SIGSYS), &info, &zero) == SIGSYS);
    CHECK(waiting(mask | bit(SIGSYS), &info, &zero) == SIGUSR1);
    record("synchronous_signal_priority");

    CHECK(kill(getpid(), SIGUSR1) == 0 &&
          syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR2) == 0);
    CHECK(waiting(mask | bit(SIGUSR2), &info, &zero) == SIGUSR2 && info.si_code == SI_TKILL);
    CHECK(waiting(mask | bit(SIGUSR2), &info, &zero) == SIGUSR1 && info.si_code == SI_USER);
    record("thread_queue_before_process_queue");

    pid_t parent = getpid(), first = fork();
    CHECK(first >= 0);
    if (!first) {
        CHECK(kill(parent, SIGUSR1) == 0);
        _exit(0);
    }
    reaped(first);
    pid_t second = fork();
    CHECK(second >= 0);
    if (!second) {
        CHECK(kill(parent, SIGUSR1) == 0);
        _exit(0);
    }
    reaped(second);
    CHECK(waiting(mask, &info, &zero) == SIGUSR1 && info.si_pid == first);
    CHECK(waiting(mask, &info, &zero) == -1 && errno == EAGAIN);
    record("coalesced_standard_signal_keeps_first_sender");

    CHECK(signal(SIGUSR1, SIG_IGN) != SIG_ERR);
    first = sender(SIGUSR1);
    struct timespec limit = {2, 0};
    CHECK(waiting(mask, &info, &limit) == SIGUSR1 && info.si_pid == first);
    reaped(first);
    record("blocked_ignored_signal_wakes_waiter");

    first = sender(SIGUSR1);
    struct timespec huge = {INT64_MAX, 999999999};
    CHECK(waiting(mask, &info, &huge) == SIGUSR1 && info.si_pid == first);
    reaped(first);
    record("saturated_timeout_accepts_delayed_signal");

    struct timespec finite = {0, 30000000};
    uint64_t started = milliseconds();
    CHECK(waiting(mask, &info, &finite) == -1 && errno == EAGAIN);
    uint64_t elapsed = milliseconds() - started;
    CHECK(elapsed >= 30 && elapsed < 2000);
    record("finite_relative_monotonic_timeout");

    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_RESTART};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGALRM, &action, NULL) == 0);
    first = sender(SIGALRM);
    CHECK(waiting(mask, &info, NULL) == -1 && errno == EINTR && caught == SIGALRM);
    reaped(first);
    record("caught_signal_is_not_restarted");

    first = fork();
    CHECK(first >= 0);
    if (!first) {
        pause_short();
        CHECK(kill(parent, SIGSTOP) == 0);
        pause_short();
        CHECK(kill(parent, SIGCONT) == 0);
        _exit(0);
    }
    CHECK(waiting(mask, &info, &limit) == -1 && errno == EINTR);
    reaped(first);
    record("stop_continue_interrupts_wait");
    CHECK(observations == 12);
    printf("SIGWAIT_PASS observations=%u\n", observations);
    return 0;
}

int main(void) {
    // Namespace PID1 deliberately ignores ordinary default stop signals on Linux.
    // Exercise the same unprivileged leaf process in both native and guest runs.
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child)
        return run_tests();
    reaped(child);
    return 0;
}

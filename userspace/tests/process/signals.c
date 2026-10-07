// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "SIGNAL_FAIL line=%d: %s errno=%d\n", __LINE__, #expr, errno);         \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
static volatile sig_atomic_t seen, on_alt, child_seen;
static unsigned char alternate_stack[16384];

static void handler(int signal, siginfo_t* info, void* context) {
    volatile unsigned char local;
    uintptr_t address = (uintptr_t)&local;
    if (signal == SIGUSR1 && info->si_signo == SIGUSR1 && info->si_pid == getpid() && context)
        seen++;
    if (signal == SIGALRM)
        seen++;
    on_alt = address >= (uintptr_t)alternate_stack &&
             address < (uintptr_t)alternate_stack + sizeof(alternate_stack);
}

static void child_handler(int signal) {
    if (signal == SIGCHLD)
        child_seen++;
}

static void fault_handler(int signal, siginfo_t* info, void* context) {
    (void)context;
    _exit(signal == SIGSEGV && info->si_addr == (void*)(uintptr_t)0x12345000 ? 33 : 99);
}

static void expect_exit(pid_t child, int expected) {
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

int main(void) {
    stack_t stack = {.ss_sp = alternate_stack, .ss_size = sizeof(alternate_stack)};
    CHECK(sigaltstack(&stack, 0) == 0);
    struct sigaction action = {0};
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    CHECK(sigemptyset(&action.sa_mask) == 0);
    CHECK(sigaction(SIGUSR1, &action, 0) == 0);
    CHECK(raise(SIGUSR1) == 0);
    CHECK(seen == 1 && on_alt);
    sigset_t mask, pending;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    CHECK(sigprocmask(SIG_BLOCK, &mask, 0) == 0);
    CHECK(raise(SIGUSR1) == 0);
    CHECK(seen == 1);
    CHECK(sigpending(&pending) == 0 && sigismember(&pending, SIGUSR1) == 1);
    CHECK(sigprocmask(SIG_UNBLOCK, &mask, 0) == 0);
    CHECK(seen == 2);
    CHECK(sigprocmask(SIG_BLOCK, &mask, 0) == 0);
    CHECK(raise(SIGUSR1) == 0);
    sigset_t empty;
    sigemptyset(&empty);
    CHECK(sigsuspend(&empty) == -1 && errno == EINTR);
    CHECK(seen == 3);
    CHECK(sigprocmask(SIG_SETMASK, 0, &pending) == 0 && sigismember(&pending, SIGUSR1) == 1);
    CHECK(sigprocmask(SIG_UNBLOCK, &mask, 0) == 0);

    CHECK(sigaction(SIGALRM, &action, 0) == 0);
    struct itimerval timer = {.it_value = {0, 30000}};
    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    CHECK(setitimer(ITIMER_REAL, &timer, 0) == 0);
    char byte;
    CHECK(read(pipefd[0], &byte, 1) == -1 && errno == EINTR);
    CHECK(seen == 4);
    close(pipefd[0]);
    close(pipefd[1]);

    action.sa_flags |= SA_RESTART;
    CHECK(sigaction(SIGALRM, &action, 0) == 0);
    CHECK(pipe(pipefd) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(pipefd[0]);
        usleep(90000);
        CHECK(write(pipefd[1], "R", 1) == 1);
        _exit(0);
    }
    close(pipefd[1]);
    CHECK(setitimer(ITIMER_REAL, &timer, 0) == 0);
    CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'R');
    CHECK(seen == 5);
    close(pipefd[0]);
    expect_exit(child, 0);

    action.sa_handler = child_handler;
    action.sa_flags = SA_RESTART;
    CHECK(sigaction(SIGCHLD, &action, 0) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child)
        _exit(21);
    expect_exit(child, 21);
    CHECK(child_seen > 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        for (;;)
            pause();
    }
    CHECK(kill(child, SIGSTOP) == 0);
    int status;
    CHECK(waitpid(child, &status, WUNTRACED) == child);
    CHECK(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    CHECK(kill(child, SIGCONT) == 0);
    CHECK(waitpid(child, &status, WCONTINUED) == child && WIFCONTINUED(status));
    CHECK(kill(child, SIGTERM) == 0);
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);

    child = fork();
    CHECK(child >= 0);
    if (!child) {
        action.sa_sigaction = fault_handler;
        action.sa_flags = SA_SIGINFO;
        CHECK(sigaction(SIGSEGV, &action, 0) == 0);
        *(volatile unsigned char*)(uintptr_t)0x12345000 = 1;
        _exit(99);
    }
    expect_exit(child, 33);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        raise(SIGKILL);
        _exit(99);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
          WTERMSIG(status) == SIGKILL);
    puts("SIGNAL_TESTS_PASS");
    return 0;
}

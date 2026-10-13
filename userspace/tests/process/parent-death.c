// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "PDEATH_FAIL line=%d error=%d\n", __LINE__, errno);                    \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static const char* executable;

static void record(const char* name) {
    printf("PDEATH_OBSERVATION case=%s\n", name);
    fflush(stdout);
    observations++;
}

static int selected(void) {
    int value = -1;
    CHECK(prctl(PR_GET_PDEATHSIG, &value, 0, 0, 0) == 0);
    return value;
}

static void byte(int fd, int sending) {
    char value = 'x';
    ssize_t size;
    do {
        size = sending ? write(fd, &value, 1) : read(fd, &value, 1);
    } while (size < 0 && errno == EINTR);
    CHECK(size == 1 && value == 'x');
}

static void waited(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void signal_wait(int output, pid_t parent) {
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGUSR1);
    siginfo_t information = {0};
    CHECK(sigwaitinfo(&signals, &information) == SIGUSR1);
    CHECK(information.si_code == SI_USER && information.si_pid == parent &&
          information.si_uid == 0);
    byte(output, 1);
    _exit(0);
}

static void ordinary_parent(void) {
    int ready[2], result[2];
    CHECK(pipe(ready) == 0 && pipe(result) == 0);
    pid_t owner = fork();
    CHECK(owner >= 0);
    if (!owner) {
        close(result[0]);
        pid_t parent = getpid();
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            close(ready[0]);
            sigset_t signals;
            sigemptyset(&signals);
            sigaddset(&signals, SIGUSR1);
            CHECK(sigprocmask(SIG_BLOCK, &signals, NULL) == 0);
            CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
            byte(ready[1], 1);
            signal_wait(result[1], parent);
        }
        close(ready[1]);
        byte(ready[0], 0);
        _exit(0);
    }
    close(ready[0]);
    close(ready[1]);
    close(result[1]);
    byte(result[0], 0);
    waited(owner);
    close(result[0]);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
    record("parent_exit_signal_information");
}

struct creator {
    int output;
    pid_t child;
    int exec;
};

static void* created(void* opaque) {
    struct creator* context = opaque;
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t parent = getpid();
    context->child = fork();
    CHECK(context->child >= 0);
    if (!context->child) {
        close(ready[0]);
        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGUSR1);
        CHECK(sigprocmask(SIG_BLOCK, &signals, NULL) == 0);
        CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
        byte(ready[1], 1);
        signal_wait(context->output, parent);
    }
    close(ready[1]);
    byte(ready[0], 0);
    close(ready[0]);
    if (context->exec) {
        char* arguments[] = {(char*)executable, "--parent-exec", NULL};
        execv(executable, arguments);
        CHECK(0);
    }
    return NULL;
}

static void thread_parent(int exec) {
    int result[2];
    CHECK(pipe(result) == 0);
    pid_t owner = fork();
    CHECK(owner >= 0);
    if (!owner) {
        close(result[0]);
        struct creator context = {.output = result[1], .exec = exec};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, created, &context) == 0);
        if (exec)
            for (;;)
                pause();
        CHECK(pthread_join(thread, NULL) == 0);
        // The creating thread has ended, but its process remains alive and
        // owns/reaps this child. Group-exit-only notification would deadlock.
        waited(context.child);
        _exit(0);
    }
    close(result[1]);
    byte(result[0], 0);
    close(result[0]);
    waited(owner);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

static void inheritance(void) {
    CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(selected() == 0);
        CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR2, 0, 0, 0) == 0);
        _exit(0);
    }
    waited(child);
    CHECK(selected() == SIGUSR1);
    CHECK(prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) == 0);
    record("fork_reset_and_parent_preservation");
}

static void* thread_setting(void* unused) {
    (void)unused;
    CHECK(selected() == 0);
    CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR2, 0, 0, 0) == 0);
    CHECK(selected() == SIGUSR2);
    return NULL;
}

static void thread_local(void) {
    CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, thread_setting, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(selected() == SIGUSR1);
    CHECK(prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) == 0);
    record("thread_reset_and_private_setting");
}

static void credential_changes(void) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
        CHECK(setresuid(12345, -1, -1) == 0 && selected() == SIGUSR1);
        CHECK(setresuid(0, -1, -1) == 0 && selected() == SIGUSR1);
        CHECK(setresuid(-1, -1, 12345) == 0 && selected() == SIGUSR1);
        CHECK(setresuid(-1, -1, 0) == 0 && selected() == SIGUSR1);
        CHECK(setfsuid(12345) == 0 && selected() == 0);
        CHECK(setfsuid(0) == 12345);
        CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
        CHECK(setfsgid(12345) == 0 && selected() == 0);
        CHECK(setfsgid(0) == 12345);
        CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
        CHECK(setresgid(-1, 12345, -1) == 0 && selected() == 0);
        CHECK(setresgid(-1, 0, -1) == 0);
        CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
        CHECK(setresuid(-1, 12345, -1) == 0 && selected() == 0);
        CHECK(setresuid(-1, 0, -1) == 0);
        CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
        CHECK(setresuid(-1, 0, -1) == 0 && selected() == SIGUSR1);
        _exit(0);
    }
    waited(child);
    record("credential_clear_and_unchanged_identity");
}

static void exec_setting(void) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && selected() == SIGUSR1);
        char* arguments[] = {(char*)executable, "--kept-exec", NULL};
        execv(executable, arguments);
        CHECK(0);
    }
    waited(child);
    record("ordinary_exec_preserves_setting");
}

int main(int argc, char** argv) {
    executable = argv[0];
    if (argc == 2 && !strcmp(argv[1], "--parent-exec"))
        return 0;
    if (argc == 2 && !strcmp(argv[1], "--kept-exec")) {
        CHECK(selected() == SIGUSR1);
        return 0;
    }
    alarm(20);
    CHECK(getuid() == 0 && geteuid() == 0 && selected() == 0);
    for (int number = 0; number <= 64; number++) {
        CHECK(prctl(PR_SET_PDEATHSIG, (unsigned long)number, 1ul, 2ul, 3ul) == 0);
        CHECK(selected() == number);
    }
    CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
    errno = 0;
    CHECK(prctl(PR_SET_PDEATHSIG, 65ul, 0, 0, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(prctl(PR_SET_PDEATHSIG, 0x100000009ul, 0, 0, 0) == -1 && errno == EINVAL);
    errno = 0;
    CHECK(prctl(PR_GET_PDEATHSIG, (void*)1, 0, 0, 0) == -1 && errno == EFAULT);
    CHECK(selected() == SIGUSR1);
    CHECK(prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) == 0);
    record("signal_range_extra_arguments_and_user_faults");
    inheritance();
    thread_local();
    credential_changes();
    exec_setting();
    ordinary_parent();
    thread_parent(0);
    record("creator_thread_exit_before_process_exit");
    thread_parent(1);
    record("creator_worker_exec_then_exit");
    for (unsigned cycle = 0; cycle < 128; cycle++)
        thread_parent(0);
    record("reclaimed_parent_threads_128_cycles");
    CHECK(observations == 9);
    puts("PDEATH_PASS observations=9");
    return 0;
}

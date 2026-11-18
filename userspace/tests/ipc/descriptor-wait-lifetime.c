// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "WAIT_LIFETIME_FAIL line=%d errno=%d %s\n", __LINE__, errno,           \
                    #condition);                                                                   \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

enum wait_call { WAIT_POLL, WAIT_PPOLL, WAIT_SELECT, WAIT_PSELECT };

enum exit_path { EVENT, SIGNAL, TIMEOUT };

static const char* const names[] = {"poll", "ppoll", "select", "pselect"};

struct wait_case {
    enum wait_call call;
    int watched, sync;
    int result, error, ready;
    int64_t elapsed;
};

static int64_t now(void) {
    struct timespec time;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
    return (int64_t)time.tv_sec * 1000000000 + time.tv_nsec;
}

static void* worker(void* argument) {
    struct wait_case* test = argument;
    struct pollfd descriptor = {.fd = test->watched, .events = POLLIN, .revents = -1};
    struct timespec nano = {0, 500000000};
    struct timeval micro = {0, 500000};
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(test->watched, &readable);
    CHECK(write(test->sync, "R", 1) == 1);
    int64_t start = now();
    switch (test->call) {
    case WAIT_POLL:
        test->result = poll(&descriptor, 1, 500);
        break;
    case WAIT_PPOLL:
        test->result = syscall(SYS_ppoll, &descriptor, 1, &nano, NULL, 0);
        break;
    case WAIT_SELECT:
        test->result = syscall(SYS_select, test->watched + 1, &readable, NULL, NULL, &micro);
        break;
    case WAIT_PSELECT:
        test->result = syscall(SYS_pselect6, test->watched + 1, &readable, NULL, NULL, &nano, NULL);
        break;
    }
    test->error = test->result < 0 ? errno : 0;
    test->elapsed = now() - start;
    test->ready =
        test->call < WAIT_SELECT ? descriptor.revents : !!FD_ISSET(test->watched, &readable);
    CHECK(write(test->sync, "D", 1) == 1);
    return NULL;
}

static void one_byte(int fd, char expected) {
    char value;
    CHECK(read(fd, &value, 1) == 1 && value == expected);
}

static void handle_signal(int signal) {
    (void)signal;
}

static void watch_description(enum wait_call call, int use_socket, int reuse, enum exit_path path) {
    int watched[2], control[2], replacement[2] = {-1, -1};
    CHECK((use_socket ? socketpair(AF_UNIX, SOCK_STREAM, 0, watched) : pipe(watched)) == 0);
    CHECK(pipe(control) == 0);
    if (reuse) {
        CHECK(pipe(replacement) == 0);
        if (path == EVENT)
            CHECK(write(replacement[1], "N", 1) == 1);
    }

    struct wait_case test = {.call = call, .watched = watched[0], .sync = control[1]};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, &test) == 0);
    one_byte(control[0], 'R');
    struct pollfd ack = {.fd = control[0], .events = POLLIN};
    CHECK(poll(&ack, 1, 75) == 0);
    CHECK(close(watched[0]) == 0);
    if (reuse)
        CHECK(dup2(replacement[0], watched[0]) == watched[0] && close(replacement[0]) == 0);
    CHECK(poll(&ack, 1, 75) == 0);

    if (path == EVENT) {
        CHECK(write(watched[1], "O", 1) == 1);
    } else {
        struct pollfd peer = {.fd = watched[1], .events = POLLOUT};
        CHECK(poll(&peer, 1, 0) == 1 && peer.revents == POLLOUT);
        if (path == SIGNAL)
            CHECK(pthread_kill(thread, SIGUSR1) == 0);
    }
    CHECK(poll(&ack, 1, 1000) == 1);
    one_byte(control[0], 'D');
    CHECK(pthread_join(thread, NULL) == 0);

    if (path == EVENT) {
        int expected = call >= WAIT_SELECT ? 1 : reuse ? POLLIN : POLLNVAL;
        CHECK(test.result == 1 && test.error == 0 && test.ready == expected);
        if (reuse)
            one_byte(watched[0], 'N');
    } else if (path == SIGNAL) {
        CHECK(test.result == -1 && test.error == EINTR);
        CHECK(test.ready == (call >= WAIT_SELECT));
    } else {
        CHECK(test.result == 0 && test.error == 0 && test.ready == 0);
        CHECK(test.elapsed >= 500000000);
    }

    CHECK(write(watched[1], "X", 1) == -1 && errno == EPIPE);
    CHECK(close(watched[1]) == 0 && close(control[0]) == 0 && close(control[1]) == 0);
    if (reuse)
        CHECK(close(watched[0]) == 0 && close(replacement[1]) == 0);
    const char* scenario = use_socket        ? "socket-close"
                           : path == SIGNAL  ? "interrupt"
                           : path == TIMEOUT ? "timeout"
                           : reuse           ? "pipe-reuse"
                                             : "pipe-close";
    printf("WAIT_LIFETIME_CASE %s-%s\n", names[call], scenario);
}

static void task_exit(enum wait_call call) {
    int watched[2], control[2];
    CHECK(pipe(watched) == 0 && pipe(control) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(watched[1]) == 0 && close(control[0]) == 0);
        struct wait_case test = {.call = call, .watched = watched[0], .sync = control[1]};
        worker(&test);
        _Exit(1);
    }
    CHECK(close(watched[0]) == 0 && close(control[1]) == 0);
    one_byte(control[0], 'R');
    struct pollfd ack = {.fd = control[0], .events = POLLIN};
    CHECK(poll(&ack, 1, 75) == 0);
    CHECK(kill(child, SIGKILL) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
          WTERMSIG(status) == SIGKILL);
    CHECK(write(watched[1], "X", 1) == -1 && errno == EPIPE);
    CHECK(close(watched[1]) == 0 && close(control[0]) == 0);
    printf("WAIT_LIFETIME_CASE %s-task-exit\n", names[call]);
}

int main(int argc, char** argv) {
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    alarm(24);
    if (argc == 2 && !strcmp(argv[1], "--ordinary"))
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    else
        CHECK(argc == 1);
    struct sigaction action = {.sa_handler = handle_signal};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, NULL) == 0);
    CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    for (enum wait_call call = WAIT_POLL; call <= WAIT_PSELECT; ++call) {
        watch_description(call, 0, 0, EVENT);
        watch_description(call, 0, 1, EVENT);
        watch_description(call, 1, 0, EVENT);
        watch_description(call, 0, 1, SIGNAL);
        watch_description(call, 0, 1, TIMEOUT);
        task_exit(call);
    }
    printf("WAIT_LIFETIME_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}

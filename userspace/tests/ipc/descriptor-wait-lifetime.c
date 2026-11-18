// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
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

enum socket_form { STREAM, DATAGRAM, NAMED_DATAGRAM };

static const char* const names[] = {"poll", "ppoll", "select", "pselect"};

struct wait_case {
    enum wait_call call;
    int watched, sync;
    short events;
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
    short events = test->events ? test->events : POLLIN;
    struct pollfd descriptor = {.fd = test->watched, .events = events, .revents = -1};
    struct timespec nano = {0, 500000000};
    struct timeval micro = {0, 500000};
    fd_set active;
    FD_ZERO(&active);
    FD_SET(test->watched, &active);
    fd_set* input = events & POLLOUT ? NULL : &active;
    fd_set* output = events & POLLOUT ? &active : NULL;
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
        test->result = syscall(SYS_select, test->watched + 1, input, output, NULL, &micro);
        break;
    case WAIT_PSELECT:
        test->result = syscall(SYS_pselect6, test->watched + 1, input, output, NULL, &nano, NULL);
        break;
    }
    test->error = test->result < 0 ? errno : 0;
    test->elapsed = now() - start;
    test->ready =
        test->call < WAIT_SELECT ? descriptor.revents : !!FD_ISSET(test->watched, &active);
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

static void socket_read_pulse(enum wait_call call, int sender, int receiver) {
    char sent = 'O', received = 0;
    struct iovec input = {.iov_base = &sent, .iov_len = 1};
    struct iovec output = {.iov_base = &received, .iov_len = 1};
    struct msghdr send_header = {.msg_iov = &input, .msg_iovlen = 1};
    struct msghdr recv_header = {.msg_iov = &output, .msg_iovlen = 1};
    switch (call) {
    case WAIT_POLL:
        CHECK(write(sender, &sent, 1) == 1 && read(receiver, &received, 1) == 1);
        break;
    case WAIT_PPOLL:
        CHECK(writev(sender, &input, 1) == 1 && readv(receiver, &output, 1) == 1);
        break;
    case WAIT_SELECT:
        CHECK(sendmsg(sender, &send_header, 0) == 1 && recvmsg(receiver, &recv_header, 0) == 1);
        break;
    case WAIT_PSELECT:
        CHECK(send(sender, &sent, 1, 0) == 1 && recv(receiver, &received, 1, 0) == 1);
        break;
    }
    CHECK(received == sent);
}

static void fill_socket(int fd, int named) {
    static const char bytes[4096] = {0};
    for (int attempt = 0; attempt < 1024; ++attempt) {
        ssize_t sent = send(fd, bytes, named ? 1 : sizeof(bytes), MSG_DONTWAIT);
        if (sent < 0) {
            CHECK(errno == EAGAIN);
            return;
        }
        CHECK(sent > 0);
    }
    CHECK(0);
}

static void drain_socket(int fd) {
    char bytes[4096];
    for (int attempt = 0; attempt < 1024; ++attempt) {
        ssize_t read = recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT);
        if (read < 0) {
            CHECK(errno == EAGAIN);
            return;
        }
        CHECK(read > 0);
    }
    CHECK(0);
}

static void transient_socket(enum wait_call call, enum socket_form form, int writable,
                             int peek_wake) {
    int endpoints[2], control[2], replacement[2];
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    socklen_t address_length = 0;
    if (form == NAMED_DATAGRAM) {
        endpoints[0] = socket(AF_UNIX, SOCK_DGRAM, 0);
        endpoints[1] = socket(AF_UNIX, SOCK_DGRAM, 0);
        CHECK(endpoints[0] >= 0 && endpoints[1] >= 0);
        int length = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                              "axiom-wait-dgram-%ld", (long)getpid());
        CHECK(length > 0 && (size_t)length < sizeof(address.sun_path) - 1);
        address_length = offsetof(struct sockaddr_un, sun_path) + length + 1;
        CHECK(bind(endpoints[writable], (void*)&address, address_length) == 0);
        if (writable)
            CHECK(connect(endpoints[0], (void*)&address, address_length) == 0);
    } else {
        CHECK(socketpair(AF_UNIX, form == STREAM ? SOCK_STREAM : SOCK_DGRAM, 0, endpoints) == 0);
    }
    CHECK(pipe(control) == 0 && pipe(replacement) == 0);
    short events = writable ? POLLOUT | POLLWRNORM : POLLIN | POLLRDNORM;
    struct pollfd original = {.fd = endpoints[0], .events = events};
    if (writable)
        fill_socket(endpoints[0], form == NAMED_DATAGRAM);
    else
        CHECK(write(replacement[1], "N", 1) == 1);
    CHECK(poll(&original, 1, 0) == 0);
    int alias = dup(endpoints[0]);
    CHECK(alias >= 0);
    struct wait_case test = {
        .call = call, .watched = endpoints[0], .sync = control[1], .events = events};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, worker, &test) == 0);
    one_byte(control[0], 'R');
    struct pollfd ack = {.fd = control[0], .events = POLLIN};
    CHECK(poll(&ack, 1, 65) == 0);
    CHECK(dup2(replacement[writable], endpoints[0]) == endpoints[0]);
    CHECK(poll(&ack, 1, 65) == 0);

    if (writable) {
        if (form != NAMED_DATAGRAM || peek_wake) {
            char peek;
            CHECK(recv(endpoints[1], &peek, 1, MSG_PEEK) == 1);
            if (!peek_wake)
                CHECK(poll(&ack, 1, 65) == 0);
        }
        if (!peek_wake) {
            drain_socket(endpoints[1]);
            fill_socket(alias, form == NAMED_DATAGRAM);
        }
        original.fd = alias;
        CHECK(poll(&original, 1, 0) == 0);
    } else if (form == NAMED_DATAGRAM) {
        char unused;
        CHECK(sendto(endpoints[1], "", 0, 0, (void*)&address, address_length) == 0);
        CHECK(recv(alias, &unused, 1, 0) == 0);
    } else {
        socket_read_pulse(call, endpoints[1], alias);
    }
    // Both original directions are unready again. An early result comes
    // from a wakeup from the original socket before the 500 ms deadline.
    int early = poll(&ack, 1, 120);
    if (peek_wake) {
        CHECK(early == 0 || early == 1);
        printf("WAIT_LIFETIME_PEEK call=%s early=%d\n", names[call], early);
        CHECK(poll(&ack, 1, 1000) == 1);
    } else {
        CHECK(early == 1);
    }
    one_byte(control[0], 'D');
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(test.result == 1 && test.error == 0 && test.ready == (call >= WAIT_SELECT ? 1 : events));
    if (!writable)
        one_byte(endpoints[0], 'N');
    CHECK(close(alias) == 0 && close(endpoints[0]) == 0 && close(endpoints[1]) == 0);
    CHECK(close(control[0]) == 0 && close(control[1]) == 0);
    CHECK(close(replacement[0]) == 0 && close(replacement[1]) == 0);
    const char* name = form == STREAM ? "socket" : form == DATAGRAM ? "datagram" : "named-datagram";
    const char* event = peek_wake ? "peek" : writable ? "write" : "read";
    printf("WAIT_LIFETIME_CASE %s-%s-%s-pulse\n", names[call], name, event);
}

static void socket_poll_masks(void) {
    int pair[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    struct pollfd selected = {.fd = pair[0], .events = POLLRDNORM | POLLWRNORM | POLLRDHUP};
    CHECK(poll(&selected, 1, 0) == 1 && selected.revents == POLLWRNORM);
    CHECK(write(pair[1], "W", 1) == 1);
    CHECK(poll(&selected, 1, 0) == 1 && selected.revents == (POLLRDNORM | POLLWRNORM));
    one_byte(pair[0], 'W');
    CHECK(shutdown(pair[1], SHUT_WR) == 0);
    CHECK(poll(&selected, 1, 0) == 1 && selected.revents == (POLLRDNORM | POLLWRNORM | POLLRDHUP));
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    puts("WAIT_LIFETIME_CASE socket-poll-masks");
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
        for (enum socket_form form = STREAM; form <= NAMED_DATAGRAM; ++form) {
            transient_socket(call, form, 0, 0);
            transient_socket(call, form, 1, 0);
        }
        transient_socket(call, NAMED_DATAGRAM, 1, 1);
    }
    socket_poll_masks();
    printf("WAIT_LIFETIME_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}

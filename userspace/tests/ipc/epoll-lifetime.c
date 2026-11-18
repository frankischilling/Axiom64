// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "EPOLL_LIFETIME_FAIL line=%d errno=%d %s\n", __LINE__, errno,          \
                    #condition);                                                                   \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static void watch(int epoll, int fd, unsigned token) {
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u32 = token};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &event) == 0);
}

static long wait2(int epoll, struct epoll_event* events, int maximum,
                  const struct timespec* timeout, const sigset_t* mask, size_t size) {
    return syscall(SYS_epoll_pwait2, epoll, events, maximum, timeout, mask, size);
}

static void expect_event(int epoll, unsigned token) {
    struct epoll_event event;
    CHECK(epoll_wait(epoll, &event, 1, 1000) == 1);
    CHECK(event.data.u32 == token && event.events == EPOLLIN);
}

static void expect_byte(int fd, char byte) {
    char observed = 0;
    CHECK(read(fd, &observed, 1) == 1 && observed == byte);
}

static void expect_child(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void descriptor_keys(void) {
    int original[2], replacement[2];
    CHECK(pipe2(original, O_NONBLOCK) == 0 && pipe2(replacement, O_NONBLOCK) == 0);
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    watch(epoll, original[0], 31);
    int alias = dup(original[0]);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u32 = 31};
    CHECK(alias >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, original[0], &event) == -1 &&
          errno == EEXIST);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, epoll, &event) == -1 && errno == EINVAL);
    CHECK(epoll_wait(original[0], &event, 1, 0) == -1 && errno == EINVAL);
    CHECK(close(original[0]) == 0 && write(original[1], "A", 1) == 1);
    expect_event(epoll, 31);
    expect_byte(alias, 'A');
    puts("EPOLL_LIFETIME_CASE retained-alias");

    CHECK(dup2(replacement[0], original[0]) == original[0]);
    watch(epoll, original[0], 79);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_DEL, alias, NULL) == -1 && errno == ENOENT);
    CHECK(write(original[1], "O", 1) == 1);
    expect_event(epoll, 31);
    expect_byte(alias, 'O');
    event = (struct epoll_event){.events = EPOLLIN | EPOLLET, .data.u32 = 80};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_MOD, original[0], &event) == 0);
    CHECK(write(replacement[1], "N", 1) == 1);
    expect_event(epoll, 80);
    expect_byte(original[0], 'N');
    puts("EPOLL_LIFETIME_CASE same-number-different-descriptions");

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(original[0]) == 0 && close(replacement[0]) == 0);
        CHECK(write(replacement[1], "P", 1) == 1);
        expect_event(epoll, 80);
        _exit(0);
    }
    expect_child(child);
    expect_byte(replacement[0], 'P');
    CHECK(write(original[1], "Q", 1) == 1 && close(alias) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(close(original[0]) == 0 && close(original[1]) == 0);
    CHECK(close(replacement[0]) == 0 && close(replacement[1]) == 0 && close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE fork-and-final-close");
}

static void exec_alias(const char* program) {
    int tube[2];
    CHECK(pipe2(tube, O_CLOEXEC) == 0);
    int epoll = epoll_create1(0);
    int reader = dup(tube[0]);
    int writer = dup(tube[1]);
    CHECK(epoll >= 0 && reader >= 0 && writer >= 0);
    watch(epoll, tube[0], 42);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char descriptors[4][16];
        const int values[] = {epoll, tube[0], reader, writer};
        for (size_t i = 0; i < 4; i++)
            CHECK(snprintf(descriptors[i], sizeof(descriptors[i]), "%d", values[i]) > 0);
        execl(program, program, "--after-exec", descriptors[0], descriptors[1], descriptors[2],
              descriptors[3], (char*)NULL);
        _exit(2);
    }
    CHECK(close(epoll) == 0 && close(tube[0]) == 0 && close(tube[1]) == 0);
    CHECK(close(reader) == 0 && close(writer) == 0);
    expect_child(child);
    puts("EPOLL_LIFETIME_CASE exec-cloexec-alias");
}

static int transfer_descriptor(int socket, int fd) {
    char marker = 'R';
    struct iovec data = {.iov_base = &marker, .iov_len = 1};

    union {
        struct cmsghdr align;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } storage = {0};
    struct msghdr message = {
        .msg_iov = &data,
        .msg_iovlen = 1,
        .msg_control = storage.bytes,
        .msg_controllen = sizeof(storage.bytes),
    };
    if (fd >= 0) {
        struct cmsghdr* header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &fd, sizeof(fd));
        CHECK(sendmsg(socket, &message, 0) == 1);
        return fd;
    }
    marker = 0;
    CHECK(recvmsg(socket, &message, MSG_CMSG_CLOEXEC) == 1 && marker == 'R');
    CHECK(message.msg_flags == 0 || message.msg_flags == MSG_CMSG_CLOEXEC);
    struct cmsghdr* header = CMSG_FIRSTHDR(&message);
    CHECK(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
          header->cmsg_len == CMSG_LEN(sizeof(fd)));
    memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    return fd;
}

static void queued_right(void) {
    int tube[2], carry[2];
    CHECK(pipe2(tube, O_NONBLOCK) == 0 && socketpair(AF_UNIX, SOCK_DGRAM, 0, carry) == 0);
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    watch(epoll, tube[0], 51);
    CHECK(transfer_descriptor(carry[0], tube[0]) == tube[0] && close(tube[0]) == 0);
    CHECK(write(tube[1], "S", 1) == 1);
    expect_event(epoll, 51);
    int received = transfer_descriptor(carry[1], -1);
    expect_byte(received, 'S');
    CHECK(write(tube[1], "X", 1) == 1 && close(received) == 0);
    struct epoll_event event;
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(close(carry[0]) == 0 && close(carry[1]) == 0);
    CHECK(close(tube[1]) == 0 && close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE rights-in-flight");
}

struct blocked_wait {
    int epoll, control;
    int pwait2;
    const struct timespec* timeout;
    int result;
    struct epoll_event event;
};

static void* blocked_waiter(void* arg) {
    struct blocked_wait* request = arg;
    CHECK(write(request->control, "B", 1) == 1);
    if (request->pwait2)
        request->result = wait2(request->epoll, &request->event, 1, request->timeout, NULL, 0);
    else
        request->result = epoll_wait(request->epoll, &request->event, 1, 3000);
    CHECK(write(request->control, "C", 1) == 1);
    return NULL;
}

static void waiting_instance(int pwait2, const struct timespec* timeout) {
    int original[2], next[2], control[2];
    CHECK(pipe(original) == 0 && pipe(next) == 0 && pipe(control) == 0);
    int epoll = epoll_create1(0), replacement = epoll_create1(0);
    CHECK(epoll >= 0 && replacement >= 0);
    watch(epoll, original[0], 61);
    watch(replacement, next[0], 62);
    struct blocked_wait request = {
        .epoll = epoll,
        .control = control[1],
        .pwait2 = pwait2,
        .timeout = timeout,
    };
    pthread_t waiter;
    CHECK(pthread_create(&waiter, NULL, blocked_waiter, &request) == 0);
    expect_byte(control[0], 'B');
    struct pollfd observation = {.fd = control[0], .events = POLLIN};
    CHECK(poll(&observation, 1, 100) == 0);
    CHECK(close(epoll) == 0 && dup2(replacement, epoll) == epoll);
    CHECK(write(next[1], "N", 1) == 1);
    CHECK(poll(&observation, 1, 100) == 0);
    CHECK(write(original[1], "O", 1) == 1);
    expect_byte(control[0], 'C');
    CHECK(pthread_join(waiter, NULL) == 0);
    CHECK(request.result == 1 && request.event.events == EPOLLIN && request.event.data.u32 == 61);
    expect_event(epoll, 62);
    expect_byte(next[0], 'N');
    expect_byte(original[0], 'O');
    CHECK(close(original[0]) == 0 && close(original[1]) == 0);
    CHECK(close(next[0]) == 0 && close(next[1]) == 0);
    CHECK(close(control[0]) == 0 && close(control[1]) == 0);
    CHECK(close(epoll) == 0 && close(replacement) == 0);
    if (!pwait2)
        puts("EPOLL_LIFETIME_CASE blocked-instance-reuse");
    else if (timeout)
        puts("EPOLL_LIFETIME_CASE pwait2-saturating-timeout");
    else
        puts("EPOLL_LIFETIME_CASE pwait2-infinite-wait");
}

static volatile sig_atomic_t handled;

static void catch_signal(int signal) {
    handled = signal;
}

static void signals_and_timeout(void) {
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct sigaction action = {.sa_handler = catch_signal, .sa_flags = SA_RESTART}, saved;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, &saved) == 0);
    sigset_t blocked, original, temporary, actual;
    CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGUSR1) == 0);
    CHECK(sigemptyset(&temporary) == 0 && pthread_sigmask(SIG_BLOCK, &blocked, &original) == 0);
    CHECK(pthread_kill(pthread_self(), SIGUSR1) == 0 && handled == 0);
    struct epoll_event event;
    CHECK(epoll_pwait(epoll, &event, 1, 250, &temporary) == -1 && errno == EINTR);
    CHECK(handled == SIGUSR1 && pthread_sigmask(SIG_SETMASK, NULL, &actual) == 0);
    CHECK(sigismember(&actual, SIGUSR1) == 1);
    CHECK(epoll_pwait(epoll, &event, 1, 30, &temporary) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, NULL, &actual) == 0 && sigismember(&actual, SIGUSR1) == 1);
    CHECK(syscall(SYS_epoll_pwait, epoll, &event, 1, 0, &temporary, 7) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_epoll_pwait, epoll, &event, 1, 0, (void*)1, 8) == -1 && errno == EFAULT);

    handled = 0;
    struct timespec timeout = {.tv_sec = 1, .tv_nsec = 12345};
    CHECK(pthread_kill(pthread_self(), SIGUSR1) == 0 && handled == 0);
    CHECK(wait2(epoll, &event, 1, &timeout, &temporary, 8) == -1 && errno == EINTR);
    CHECK(handled == SIGUSR1 && pthread_sigmask(SIG_SETMASK, NULL, &actual) == 0);
    CHECK(sigismember(&actual, SIGUSR1) == 1 && timeout.tv_sec == 1 && timeout.tv_nsec == 12345);
    puts("EPOLL_LIFETIME_CASE pwait2-signal-mask");

    CHECK(pthread_sigmask(SIG_SETMASK, &original, NULL) == 0 &&
          sigaction(SIGUSR1, &saved, NULL) == 0);

    int control[2];
    CHECK(pipe(control) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(control[0]) == 0 && write(control[1], "B", 1) == 1);
        CHECK(epoll_wait(epoll, &event, 1, 2000) == -1 && errno == EINTR);
        _exit(0);
    }
    CHECK(close(control[1]) == 0);
    expect_byte(control[0], 'B');
    CHECK(poll(&(struct pollfd){.fd = control[0], .events = POLLIN}, 1, 100) == 0);
    CHECK(kill(child, SIGSTOP) == 0);
    int status;
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    CHECK(kill(child, SIGCONT) == 0);
    expect_child(child);
    CHECK(close(control[0]) == 0 && close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE signal-mask-and-stop");
}

static void pwait2_arguments(void) {
    int epoll = epoll_create1(EPOLL_CLOEXEC), path = open("/", O_PATH | O_CLOEXEC);
    int tube[2];
    CHECK(epoll >= 0 && path >= 0 && pipe2(tube, O_NONBLOCK) == 0);
    struct epoll_event event;
    struct timespec zero = {0};
    sigset_t mask;
    CHECK(sigemptyset(&mask) == 0);
    CHECK(wait2(epoll, &event, 1, &zero, NULL, 99) == 0);
    CHECK(wait2(epoll, &event, 0, &zero, NULL, 0) == -1 && errno == EINVAL);
    CHECK(wait2(epoll, &event, -1, &zero, NULL, 0) == -1 && errno == EINVAL);
    CHECK(wait2(-1, &event, 1, &zero, NULL, 0) == -1 && errno == EBADF);
    CHECK(wait2(path, &event, 1, &zero, NULL, 0) == -1 && errno == EBADF);
    CHECK(wait2(tube[0], &event, 1, &zero, NULL, 0) == -1 && errno == EINVAL);
    CHECK(wait2(epoll, (void*)UINTPTR_MAX, 1, &zero, NULL, 0) == -1 && errno == EFAULT);
    CHECK(epoll_wait(tube[0], (void*)UINTPTR_MAX, 1, 0) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_epoll_pwait, -1, &event, 1, 0, &mask, 7) == -1 && errno == EINVAL);
    for (size_t size = 7; size < 10; size += 2)
        CHECK(wait2(-1, &event, 1, &zero, &mask, size) == -1 && errno == EINVAL);
    CHECK(wait2(-1, &event, 1, &zero, (void*)1, 8) == -1 && errno == EFAULT);

    const struct timespec invalid[] = {{-1, 0}, {0, -1}, {0, 1000000000}};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        CHECK(wait2(-1, &event, 1, &invalid[i], (void*)1, 8) == -1 && errno == EINVAL);
    CHECK(wait2(-1, &event, 1, (void*)1, &mask, 7) == -1 && errno == EFAULT);

    watch(epoll, tube[0], 71);
    CHECK(write(tube[1], "P", 1) == 1);
    CHECK(wait2(epoll, (void*)1, 1, &zero, NULL, 0) == -1 && errno == EFAULT);
    CHECK(wait2(epoll, &event, 1, &zero, &mask, 8) == 1);
    CHECK(event.events == EPOLLIN && event.data.u32 == 71);
    expect_byte(tube[0], 'P');
    CHECK(close(path) == 0 && close(tube[0]) == 0 && close(tube[1]) == 0 && close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE pwait2-arguments-and-copy");
}

static int64_t monotonic_ns(void) {
    struct timespec time;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
    return time.tv_sec * INT64_C(1000000000) + time.tv_nsec;
}

static void pwait2_deadline(void) {
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    struct timespec* timeout =
        mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(timeout != MAP_FAILED);
    int epoll = epoll_create1(0);
    CHECK(epoll >= 0);
    struct epoll_event event;
    const long durations[] = {1, 31000001};
    for (size_t i = 0; i < sizeof(durations) / sizeof(durations[0]); i++) {
        CHECK(mprotect(timeout, page, PROT_READ | PROT_WRITE) == 0);
        *timeout = (struct timespec){.tv_nsec = durations[i]};
        CHECK(mprotect(timeout, page, PROT_READ) == 0);
        int64_t start = monotonic_ns();
        CHECK(wait2(epoll, &event, 1, timeout, NULL, 0) == 0);
        int64_t elapsed = monotonic_ns() - start;
        CHECK(elapsed >= durations[i] && elapsed < INT64_C(2000000000));
        CHECK(timeout->tv_sec == 0 && timeout->tv_nsec == durations[i]);
        printf("EPOLL_LIFETIME_DEADLINE requested_ns=%ld elapsed_ns=%" PRId64 "\n", durations[i],
               elapsed);
    }
    CHECK(munmap(timeout, page) == 0 && close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE pwait2-read-only-deadline");
}

static void reclaim_and_copy_fault(void) {
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    struct epoll_event event;
    for (unsigned cycle = 0; cycle < 192; cycle++) {
        int tube[2];
        CHECK(pipe2(tube, O_NONBLOCK) == 0);
        watch(epoll, tube[0], cycle);
        CHECK(write(tube[1], "Z", 1) == 1 && close(tube[0]) == 0);
        CHECK(epoll_wait(epoll, &event, 1, 0) == 0 && close(tube[1]) == 0);
    }
    int routes[2][2];
    for (unsigned n = 0; n < 2; n++) {
        CHECK(pipe2(routes[n], O_NONBLOCK) == 0);
        watch(epoll, routes[n][0], n + 1);
        CHECK(write(routes[n][1], "F", 1) == 1);
    }
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    char* memory =
        mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && mprotect(memory + page, page, PROT_NONE) == 0);
    struct epoll_event* boundary = (struct epoll_event*)(memory + page - sizeof(event));
    CHECK(epoll_wait(epoll, boundary, 2, 0) == 1);
    unsigned first = boundary->data.u32;
    CHECK((first == 1 || first == 2) && boundary->events == EPOLLIN);
    expect_event(epoll, 3 - first);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(munmap(memory, 2 * (size_t)page) == 0);
    for (unsigned n = 0; n < 2; n++)
        CHECK(close(routes[n][0]) == 0 && close(routes[n][1]) == 0);
    CHECK(close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE reuse-and-copy-fault");
}

int main(int argc, char** argv) {
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    alarm(20);
    if (argc == 6 && strcmp(argv[1], "--after-exec") == 0) {
        int epoll = atoi(argv[2]), old = atoi(argv[3]), reader = atoi(argv[4]),
            writer = atoi(argv[5]);
        CHECK(fcntl(old, F_GETFD) == -1 && errno == EBADF);
        CHECK(write(writer, "E", 1) == 1);
        expect_event(epoll, 42);
        expect_byte(reader, 'E');
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--ordinary") == 0)
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    else
        CHECK(argc == 1);
    descriptor_keys();
    exec_alias(argv[0]);
    queued_right();
    waiting_instance(0, NULL);
    pwait2_arguments();
    waiting_instance(1, NULL);
    // An unchecked conversion of these seconds into 10 ms units wraps to zero.
    const struct timespec huge = {.tv_sec = INT64_C(1) << 62, .tv_nsec = 1};
    waiting_instance(1, &huge);
    signals_and_timeout();
    pwait2_deadline();
    reclaim_and_copy_fault();
    printf("EPOLL_LIFETIME_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}

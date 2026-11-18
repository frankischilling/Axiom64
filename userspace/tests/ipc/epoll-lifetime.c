// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/uio.h>
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

static void check_poll_mask(int fd, short requested, short expected) {
    struct pollfd test = {.fd = fd, .events = requested};
    CHECK(poll(&test, 1, 0) == 1 && test.revents == expected);
}

static void descriptor_admission(const char* program) {
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(epoll >= 0);
    const short normal = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;
    const uint32_t events = EPOLLIN | EPOLLOUT | EPOLLRDNORM | EPOLLWRNORM;
    struct epoll_event event = {.events = events, .data.u32 = 17};
    const char* defaults[] = {
        program, "/", "/dev/null", "/dev/zero", "/dev/urandom", "/proc/self/status"};
    for (size_t i = 0; i < sizeof(defaults) / sizeof(defaults[0]); i++) {
        int fd = open(defaults[i], O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0);
        CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &event) == -1 && errno == EPERM);
        CHECK(epoll_ctl(epoll, EPOLL_CTL_MOD, fd, &event) == -1 && errno == EPERM);
        CHECK(epoll_ctl(epoll, EPOLL_CTL_DEL, fd, NULL) == -1 && errno == EPERM);
        CHECK(epoll_ctl(fd, EPOLL_CTL_ADD, fd, &event) == -1 && errno == EPERM);
        CHECK(epoll_ctl(-1, EPOLL_CTL_ADD, fd, &event) == -1 && errno == EBADF);
        CHECK(epoll_ctl(-1, EPOLL_CTL_ADD, fd, (void*)1) == -1 && errno == EFAULT);
        check_poll_mask(fd, normal, normal);
        CHECK(close(fd) == 0);
    }

    int path = open("/", O_PATH | O_CLOEXEC);
    CHECK(path >= 0);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, path, &event) == -1 && errno == EBADF);
    check_poll_mask(path, normal, POLLNVAL);
    CHECK(close(path) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    puts("EPOLL_LIFETIME_CASE descriptor-admission");

    int control = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
    CHECK(control >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, control, &event) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == events && event.data.u32 == 17);
    CHECK(close(control) == 0);
    int random = open("/dev/random", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    event.events = EPOLLIN;
    CHECK(random >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, random, &event) == 0);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_DEL, random, NULL) == 0 && close(random) == 0);
    int terminal = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    event.events = EPOLLOUT;
    CHECK(terminal >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, terminal, &event) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == EPOLLOUT && event.data.u32 == 17);
    CHECK(close(terminal) == 0 && close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE pollable-controls-and-devices");
}

static void epoll_descriptor_io(int legacy_seek) {
    const uint64_t high = UINT64_C(1) << 32;
    CHECK(syscall(SYS_epoll_create, -1) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_epoll_create, high) == -1 && errno == EINVAL);
    CHECK(epoll_create1(O_NONBLOCK) == -1 && errno == EINVAL);
    int legacy = syscall(SYS_epoll_create, high | 1);
    CHECK(legacy >= 0 && fcntl(legacy, F_GETFD) == 0 && close(legacy) == 0);
    int epoll = syscall(SYS_epoll_create1, high | EPOLL_CLOEXEC);
    CHECK(epoll >= 0 && fcntl(epoll, F_GETFD) == FD_CLOEXEC);
    CHECK((fcntl(epoll, F_GETFL) & O_ACCMODE) == O_RDWR);

    struct rlimit original;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0);
    struct rlimit exhausted = {.rlim_cur = 0, .rlim_max = original.rlim_max};
    CHECK(setrlimit(RLIMIT_NOFILE, &exhausted) == 0);
    CHECK(epoll_create1(0) == -1 && errno == EMFILE);
    CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    int tube[2];
    CHECK(pipe(tube) == 0);
    struct epoll_event event = {.events = EPOLLIN, .data.u32 = 19};
    CHECK(syscall(SYS_epoll_ctl, epoll, high | EPOLL_CTL_ADD, tube[0], &event) == 0);
    CHECK(write(tube[1], "I", 1) == 1);
    expect_event(epoll, 19);
    CHECK(close(tube[0]) == 0 && close(tube[1]) == 0);
    puts("EPOLL_LIFETIME_CASE epoll-creation-and-resource-limit");

    struct stat status;
    CHECK(fstat(epoll, &status) == 0 && status.st_mode == 0600 && status.st_nlink == 1);
    CHECK(fstatat(epoll, "", &status, AT_EMPTY_PATH) == 0 && status.st_mode == 0600 &&
          status.st_nlink == 1);
    CHECK(fstatat(epoll, "", &status, 0) == -1 && errno == ENOENT);
    CHECK(fstatat(epoll, "dummy", &status, 0) == -1 && errno == ENOTDIR);
    char byte = 0;
    struct iovec vector = {.iov_base = &byte, .iov_len = 1};
    CHECK(read(epoll, &byte, 1) == -1 && errno == EINVAL);
    CHECK(read(epoll, &byte, 0) == -1 && errno == EINVAL);
    CHECK(write(epoll, &byte, 1) == -1 && errno == EINVAL);
    CHECK(write(epoll, &byte, 0) == -1 && errno == EINVAL);
    CHECK(readv(epoll, &vector, 1) == -1 && errno == EINVAL);
    CHECK(writev(epoll, &vector, 1) == -1 && errno == EINVAL);
    CHECK(pread(epoll, &byte, 1, 0) == -1 && errno == ESPIPE);
    CHECK(pwrite(epoll, &byte, 1, 0) == -1 && errno == ESPIPE);
    CHECK(pread(epoll, &byte, 1, -1) == -1 && errno == EINVAL);
    if (legacy_seek) {
        CHECK(lseek(epoll, 12, SEEK_SET) == -1 && errno == ESPIPE);
        puts("EPOLL_LIFETIME_SEEK espipe");
    } else {
        CHECK(lseek(epoll, 12, SEEK_SET) == 0);
        CHECK(lseek(epoll, 0, SEEK_CUR) == 0);
        puts("EPOLL_LIFETIME_SEEK noop");
    }
    CHECK(lseek(epoll, 0, 5) == -1 && errno == EINVAL);
    CHECK(fsync(epoll) == -1 && errno == EINVAL);
    CHECK(close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE epoll-anonymous-descriptor");
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

static void exclusive_registration(void) {
    int epoll = epoll_create1(EPOLL_CLOEXEC), tube[2];
    CHECK(epoll >= 0 && pipe2(tube, O_NONBLOCK) == 0);
    const unsigned incompatible[] = {EPOLLONESHOT, EPOLLPRI, EPOLLRDNORM};
    struct epoll_event event = {.data.u32 = 81};
    for (size_t i = 0; i < sizeof(incompatible) / sizeof(incompatible[0]); i++) {
        event.events = EPOLLIN | EPOLLEXCLUSIVE | incompatible[i];
        CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, tube[0], &event) == -1 && errno == EINVAL);
    }
    event.events = EPOLLIN | EPOLLEXCLUSIVE;
    CHECK(epoll_ctl(epoll, EPOLL_CTL_MOD, tube[0], &event) == -1 && errno == EINVAL);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, tube[0], &event) == 0);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, tube[0], &event) == -1 && errno == EEXIST);
    event.events = EPOLLIN;
    event.data.u32 = 82;
    CHECK(epoll_ctl(epoll, EPOLL_CTL_MOD, tube[0], &event) == -1 && errno == EINVAL);
    CHECK(write(tube[1], "E", 1) == 1);
    expect_event(epoll, 81);
    expect_event(epoll, 81);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_DEL, tube[0], NULL) == 0);
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, tube[0], &event) == 0);
    event.events |= EPOLLEXCLUSIVE;
    CHECK(epoll_ctl(epoll, EPOLL_CTL_MOD, tube[0], &event) == -1 && errno == EINVAL);
    expect_event(epoll, 82);
    expect_byte(tube[0], 'E');
    CHECK(close(tube[0]) == 0 && close(tube[1]) == 0 && close(epoll) == 0);
    puts("EPOLL_LIFETIME_CASE exclusive-registration");
}

struct exclusive_waiter {
    int epoll, control;
    int result;
    struct epoll_event event;
};

static void* wait_exclusively(void* arg) {
    struct exclusive_waiter* waiter = arg;
    CHECK(write(waiter->control, "B", 1) == 1);
    waiter->result = epoll_wait(waiter->epoll, &waiter->event, 1, 500);
    CHECK(write(waiter->control, "D", 1) == 1);
    return NULL;
}

static void exclusive_delivery(int target, uint32_t interest, int initially_readable,
                               void (*trigger)(int), int argument) {
    int epolls[4], control[2];
    CHECK(pipe(control) == 0);
    // The order of instance creation differs from the order of watch registration.
    for (int i = 3; i >= 0; i--) {
        epolls[i] = epoll_create1(EPOLL_CLOEXEC);
        CHECK(epolls[i] >= 0);
    }
    for (unsigned i = 0; i < 4; i++) {
        struct epoll_event event = {
            .events = interest | (i < 3 ? EPOLLEXCLUSIVE : 0),
            .data.u32 = 90 + i,
        };
        CHECK(epoll_ctl(epolls[i], EPOLL_CTL_ADD, target, &event) == 0);
        if (initially_readable)
            expect_event(epolls[i], 90 + i);
    }
    int outer = epoll_create1(EPOLL_CLOEXEC);
    CHECK(outer >= 0);
    watch(outer, epolls[0], 94);

    struct exclusive_waiter waiters[3] = {0};
    pthread_t threads[3];
    for (unsigned i = 0; i < 3; i++) {
        waiters[i].epoll = epolls[i + 1];
        waiters[i].control = control[1];
        CHECK(pthread_create(&threads[i], NULL, wait_exclusively, &waiters[i]) == 0);
    }
    for (unsigned i = 0; i < 3; i++)
        expect_byte(control[0], 'B');
    struct pollfd observer = {.fd = control[0], .events = POLLIN};
    CHECK(poll(&observer, 1, 60) == 0);
    trigger(argument);
    // A direct exclusive waiter and the ordinary waiter receive the same event.
    for (unsigned i = 0; i < 2; i++) {
        CHECK(poll(&observer, 1, 1200) == 1 && observer.revents == POLLIN);
        expect_byte(control[0], 'D');
    }
    CHECK(poll(&observer, 1, 60) == 0);
    for (unsigned i = 0; i < 3; i++)
        CHECK(pthread_join(threads[i], NULL) == 0);
    uint32_t ready = interest & (EPOLLIN | EPOLLOUT);
    CHECK(waiters[0].result == 1 && waiters[0].event.data.u32 == 91 &&
          waiters[0].event.events == ready);
    CHECK(waiters[1].result == 0);
    CHECK(waiters[2].result == 1 && waiters[2].event.data.u32 == 93 &&
          waiters[2].event.events == ready);
    struct epoll_event event;
    CHECK(epoll_wait(epolls[2], &event, 1, 0) == 0);
    expect_event(outer, 94);
    CHECK(epoll_wait(epolls[0], &event, 1, 0) == 1);
    CHECK(event.data.u32 == 90 && event.events == ready);

    CHECK(close(outer) == 0 && close(control[0]) == 0 && close(control[1]) == 0);
    for (unsigned i = 0; i < 4; i++)
        CHECK(close(epolls[i]) == 0);
}

static void wake_exclusive_pipe(int writer) {
    CHECK(write(writer, "W", 1) == 1);
}

static void wake_exclusive_eventfd(int fd) {
    uint64_t value;
    CHECK(read(fd, &value, sizeof(value)) == sizeof(value) && value == UINT64_MAX - 1);
}

static void wake_exclusive_signalfd(int pid) {
    CHECK(kill(pid, SIGUSR1) == 0);
}

static socklen_t exclusive_address(struct sockaddr_un* address) {
    *address = (struct sockaddr_un){.sun_family = AF_UNIX};
    int size = snprintf(address->sun_path + 1, sizeof(address->sun_path) - 1, "epoll-exclusive-%ld",
                        (long)getpid());
    CHECK(size > 0 && (size_t)size < sizeof(address->sun_path) - 1);
    return offsetof(struct sockaddr_un, sun_path) + 1 + size;
}

static void wake_exclusive_listener(int client) {
    struct sockaddr_un address;
    socklen_t size = exclusive_address(&address);
    CHECK(connect(client, (struct sockaddr*)&address, size) == 0);
}

static void exclusive_wakeups(void) {
    int tube[2];
    CHECK(pipe2(tube, O_NONBLOCK) == 0);
    exclusive_delivery(tube[0], EPOLLIN, 0, wake_exclusive_pipe, tube[1]);
    expect_byte(tube[0], 'W');
    CHECK(close(tube[0]) == 0 && close(tube[1]) == 0);
    puts("EPOLL_LIFETIME_CASE exclusive-pipe-readers");

    int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    uint64_t full = UINT64_MAX - 1;
    CHECK(fd >= 0 && write(fd, &full, sizeof(full)) == sizeof(full));
    exclusive_delivery(fd, EPOLLOUT, 0, wake_exclusive_eventfd, fd);
    CHECK(close(fd) == 0);
    puts("EPOLL_LIFETIME_CASE exclusive-eventfd-writers");

    sigset_t signals, original;
    CHECK(sigemptyset(&signals) == 0 && sigaddset(&signals, SIGUSR1) == 0);
    CHECK(pthread_sigmask(SIG_BLOCK, &signals, &original) == 0);
    fd = signalfd(-1, &signals, SFD_NONBLOCK | SFD_CLOEXEC);
    CHECK(fd >= 0);
    exclusive_delivery(fd, EPOLLIN, 0, wake_exclusive_signalfd, getpid());
    struct signalfd_siginfo info;
    CHECK(read(fd, &info, sizeof(info)) == sizeof(info) && info.ssi_signo == SIGUSR1);
    CHECK(close(fd) == 0 && pthread_sigmask(SIG_SETMASK, &original, NULL) == 0);
    puts("EPOLL_LIFETIME_CASE exclusive-signalfd");

    int server = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int clients[2];
    struct sockaddr_un address;
    socklen_t size = exclusive_address(&address);
    CHECK(server >= 0 && bind(server, (struct sockaddr*)&address, size) == 0);
    CHECK(listen(server, 2) == 0);
    clients[0] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    clients[1] = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(clients[0] >= 0 && clients[1] >= 0);
    wake_exclusive_listener(clients[0]);
    exclusive_delivery(server, EPOLLIN | EPOLLET, 1, wake_exclusive_listener, clients[1]);
    for (unsigned i = 0; i < 2; i++) {
        int accepted = accept4(server, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        CHECK(accepted >= 0 && write(clients[i], "A", 1) == 1);
        expect_byte(accepted, 'A');
        CHECK(close(accepted) == 0 && close(clients[i]) == 0);
    }
    CHECK(close(server) == 0);
    puts("EPOLL_LIFETIME_CASE exclusive-listener-backlog");
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
    int legacy_seek = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ordinary") == 0) {
            CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        } else {
            CHECK(strcmp(argv[i], "--legacy-seek") == 0);
            legacy_seek = 1;
        }
    }
    descriptor_admission(argv[0]);
    epoll_descriptor_io(legacy_seek);
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
    exclusive_registration();
    exclusive_wakeups();
    reclaim_and_copy_fault();
    printf("EPOLL_LIFETIME_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}

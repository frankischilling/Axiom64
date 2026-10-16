// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "EVENTFD_FAIL line=%d expression=%s errno=%d\n", __LINE__, #value,     \
                    errno);                                                                        \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static uint64_t take(int fd) {
    uint64_t value;
    CHECK(read(fd, &value, sizeof(value)) == sizeof(value));
    return value;
}

static void put(int fd, uint64_t value) {
    CHECK(write(fd, &value, sizeof(value)) == sizeof(value));
}

static void empty(int fd) {
    uint64_t value;
    errno = 0;
    CHECK(read(fd, &value, sizeof(value)) == -1 && errno == EAGAIN);
}

static void creation(void) {
    CHECK(syscall(SYS_eventfd2, 0, 2) == -1 && errno == EINVAL);
    int fd = syscall(SYS_eventfd, (1UL << 40) | 7);
    CHECK(fd >= 0 && take(fd) == 7 && close(fd) == 0);
    fd = syscall(SYS_eventfd2, (1UL << 40) | 9, (1UL << 40) | EFD_CLOEXEC | EFD_NONBLOCK);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    CHECK(fcntl(fd, F_GETFL) == (O_RDWR | O_NONBLOCK) && take(fd) == 9);
    int nonblock = 0;
    CHECK(ioctl(fd, FIONBIO, &nonblock) == 0 && fcntl(fd, F_GETFL) == O_RDWR);
    nonblock = 1;
    CHECK(ioctl(fd, FIONBIO, &nonblock) == 0 && (fcntl(fd, F_GETFL) & O_NONBLOCK));
    CHECK(ioctl(fd, FIONREAD, &nonblock) == -1 && errno == ENOTTY);
    struct stat metadata;
    CHECK(fstat(fd, &metadata) == 0 && metadata.st_mode == 0600 && metadata.st_size == 0 &&
          metadata.st_nlink == 1 && metadata.st_uid == 0 && metadata.st_gid == 0);
    for (int whence = 0; whence <= 4; whence++)
        CHECK(lseek(fd, -123, whence) == 0);
    CHECK(lseek(fd, 0, 5) == -1 && errno == EINVAL);
    uint64_t value = 0;
    CHECK(pread(fd, &value, sizeof(value), 0) == -1 && errno == ESPIPE);
    CHECK(pwrite(fd, &value, sizeof(value), 0) == -1 && errno == ESPIPE);
    CHECK(close(fd) == 0);
    struct rlimit original, limited;
    CHECK(getrlimit(RLIMIT_NOFILE, &original) == 0);
    limited = original;
    limited.rlim_cur = 3;
    CHECK(setrlimit(RLIMIT_NOFILE, &limited) == 0);
    CHECK(eventfd(0, 0) == -1 && errno == EMFILE);
    CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
    for (int iteration = 0; iteration < 1000; iteration++) {
        fd = eventfd(1, EFD_NONBLOCK);
        CHECK(fd >= 0 && take(fd) == 1 && close(fd) == 0);
    }
    puts("EVENTFD_GROUP_PASS creation");
}

static void counters(int strict) {
    int fd = eventfd(2, EFD_NONBLOCK);
    CHECK(fd >= 0);
    put(fd, 5);
    uint64_t output[2] = {0, UINT64_MAX};
    CHECK(read(fd, output, sizeof(output)) == 8 && output[0] == 7 && output[1] == UINT64_MAX);
    empty(fd);
    CHECK(write(fd, output, 4) == -1 && errno == EINVAL);
    CHECK(read(fd, output, 4) == -1 && errno == EINVAL);
    output[0] = 3;
    errno = 0;
    ssize_t oversized = write(fd, output, sizeof(output));
    int error = errno;
    CHECK((oversized == -1 && error == EINVAL) || (!strict && oversized == 8));
    printf("EVENTFD_WRITE_SIZE strict=%d result=%ld errno=%d\n", strict, (long)oversized, error);
    if (oversized == 8)
        CHECK(take(fd) == 3);
    empty(fd);
    put(fd, UINT64_MAX - 1);
    struct pollfd ready = {fd, POLLIN | POLLOUT, 0};
    CHECK(poll(&ready, 1, 0) == 1 && ready.revents == POLLIN);
    put(fd, 0);
    output[0] = 1;
    CHECK(write(fd, output, 8) == -1 && errno == EAGAIN);
    output[0] = UINT64_MAX;
    CHECK(write(fd, output, 8) == -1 && errno == EINVAL);
    CHECK(take(fd) == UINT64_MAX - 1 && close(fd) == 0);
    fd = eventfd(3, EFD_SEMAPHORE | EFD_NONBLOCK);
    CHECK(fd >= 0);
    for (int i = 0; i < 3; i++) {
        CHECK(take(fd) == 1);
        ready = (struct pollfd){fd, POLLIN | POLLOUT, 0};
        CHECK(poll(&ready, 1, 0) == 1 && ready.revents == (POLLOUT | (i == 2 ? 0 : POLLIN)));
    }
    empty(fd);
    CHECK(close(fd) == 0);
    puts("EVENTFD_GROUP_PASS counters");
}

static void faults_and_vectors(void) {
    int fd = eventfd(9, EFD_NONBLOCK);
    CHECK(fd >= 0);
    CHECK(syscall(SYS_read, fd, (void*)1, 8) == -1 && errno == EFAULT);
    empty(fd);
    CHECK(syscall(SYS_read, fd, (void*)1, 8) == -1 && errno == EAGAIN);
    CHECK(syscall(SYS_read, fd, (void*)1, 0) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_write, fd, (void*)1, 0) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_write, fd, (void*)1, 8) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_read, fd, (void*)UINTPTR_MAX, 0) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_readv, fd, (void*)1, 0) == 0);
    CHECK(syscall(SYS_writev, fd, (void*)1, 0) == 0);
    uint64_t value = 3;
    struct iovec split[2] = {{&value, 4}, {(char*)&value + 4, 4}};
    CHECK(writev(fd, split, 2) == -1 && errno == EINVAL);
    split[0] = split[1] = (struct iovec){&value, 8};
    CHECK(writev(fd, split, 2) == 16);
    uint64_t output[2] = {UINT64_MAX, UINT64_MAX};
    split[0] = (struct iovec){output, 4};
    split[1] = (struct iovec){(char*)output + 4, 12};
    CHECK(readv(fd, split, 2) == 8 && output[0] == 6 && output[1] == UINT64_MAX);
    put(fd, 7);
    split[1] = (struct iovec){(void*)1, 4};
    CHECK(readv(fd, split, 2) == -1 && errno == EFAULT);
    CHECK((uint32_t)output[0] == 7);
    empty(fd);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    char* mapped = mmap(0, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapped != MAP_FAILED && mprotect(mapped + page, page, PROT_NONE) == 0);
    put(fd, 13);
    CHECK(read(fd, mapped + page - 4, 8) == -1 && errno == EFAULT);
    uint32_t prefix;
    memcpy(&prefix, mapped + page - 4, 4);
    CHECK(prefix == 13);
    empty(fd);
    CHECK(munmap(mapped, page * 2) == 0 && close(fd) == 0);
    puts("EVENTFD_GROUP_PASS faults-vectors");
}

static void readiness(void) {
    int fd = eventfd(0, EFD_NONBLOCK), poller = epoll_create1(EPOLL_CLOEXEC);
    CHECK(fd >= 0 && poller >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u64 = 0x12345678};
    CHECK(epoll_ctl(poller, EPOLL_CTL_ADD, fd, &event) == 0);
    CHECK(epoll_wait(poller, &event, 1, 0) == 0);
    fd_set input, output;
    FD_ZERO(&input);
    FD_ZERO(&output);
    FD_SET(fd, &input);
    FD_SET(fd, &output);
    struct timeval timeout = {0};
    CHECK(select(fd + 1, &input, &output, 0, &timeout) == 1 && !FD_ISSET(fd, &input) &&
          FD_ISSET(fd, &output));
    for (unsigned i = 0; i < 2; i++) {
        put(fd, 1);
        CHECK(epoll_wait(poller, &event, 1, 1000) == 1 && event.events == EPOLLIN &&
              event.data.u64 == 0x12345678);
        CHECK(epoll_wait(poller, &event, 1, 0) == 0 && take(fd) == 1);
        CHECK(epoll_wait(poller, &event, 1, 0) == 0);
    }
    put(fd, 1);
    CHECK(take(fd) == 1 && epoll_wait(poller, &event, 1, 0) == 0);
    put(fd, 1);
    CHECK(epoll_wait(poller, &event, 1, 0) == 1 && event.events == EPOLLIN && take(fd) == 1);
    put(fd, 1);
    CHECK(epoll_wait(poller, &event, 1, 0) == 1 && event.events == EPOLLIN);
    put(fd, 1);
    CHECK(epoll_wait(poller, &event, 1, 0) == 1 && event.events == EPOLLIN && take(fd) == 2);
    event.events = EPOLLOUT | EPOLLET;
    CHECK(epoll_ctl(poller, EPOLL_CTL_MOD, fd, &event) == 0);
    CHECK(epoll_wait(poller, &event, 1, 0) == 1 && event.events == EPOLLOUT);
    put(fd, 1);
    CHECK(epoll_wait(poller, &event, 1, 0) == 0 && take(fd) == 1);
    CHECK(epoll_wait(poller, &event, 1, 0) == 1 && event.events == EPOLLOUT);
    CHECK(epoll_ctl(poller, EPOLL_CTL_DEL, fd, 0) == 0 && close(poller) == 0 && close(fd) == 0);
    puts("EVENTFD_GROUP_PASS readiness");
}

struct Operation {
    int fd, write, error;
    ssize_t result;
    uint64_t output;
    atomic_uint_fast64_t input;
    atomic_int tid, done;
};

static void* operate(void* pointer) {
    struct Operation* operation = pointer;
    atomic_store(&operation->tid, (int)syscall(SYS_gettid));
    errno = 0;
    operation->result = operation->write ? write(operation->fd, &operation->input, 8)
                                         : read(operation->fd, &operation->output, 8);
    operation->error = errno;
    atomic_store(&operation->done, 1);
    return 0;
}

static void sleeping(struct Operation* operation) {
    for (int iteration = 0; iteration < 5000; iteration++) {
        int tid = atomic_load(&operation->tid);
        if (tid) {
            char path[64], text[2048];
            snprintf(path, sizeof(path), "/proc/%d/status", tid);
            int descriptor = open(path, O_RDONLY);
            CHECK(descriptor >= 0);
            ssize_t length = read(descriptor, text, sizeof(text) - 1);
            CHECK(length > 0 && close(descriptor) == 0);
            text[length] = 0;
            char* state = strstr(text, "\nState:");
            CHECK(state);
            state += strlen("\nState:");
            while (*state == ' ' || *state == '\t')
                state++;
            if (*state == 'S') {
                CHECK(!atomic_load(&operation->done));
                return;
            }
        }
        CHECK(!atomic_load(&operation->done));
        usleep(1000);
    }
    CHECK(0 && "eventfd operation did not enter its actual kernel wait");
}

static void retained_io(void) {
    int original = eventfd(0, 0), alias = dup(original), replacement = eventfd(5, EFD_NONBLOCK);
    CHECK(original >= 0 && alias >= 0 && replacement >= 0);
    struct Operation operation = {.fd = original};
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, operate, &operation) == 0);
    sleeping(&operation);
    CHECK(close(original) == 0 && dup2(replacement, original) == original);
    put(alias, 17);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == 8 && operation.output == 17);
    CHECK(take(original) == 5 && close(original) == 0 && close(alias) == 0 &&
          close(replacement) == 0);
    int fd = eventfd(0, 0);
    CHECK(fd >= 0);
    put(fd, UINT64_MAX - 1);
    operation = (struct Operation){.fd = fd, .write = 1};
    atomic_store(&operation.input, 7);
    CHECK(pthread_create(&thread, 0, operate, &operation) == 0);
    sleeping(&operation);
    atomic_store(&operation.input, 29);
    CHECK(take(fd) == UINT64_MAX - 1);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == 8 && take(fd) == 7);
    CHECK(close(fd) == 0);
    puts("EVENTFD_GROUP_PASS retained-io");
}

static volatile sig_atomic_t signals;

static void handler(int number) {
    signals += number == SIGUSR1;
}

static void interruption(void) {
    struct sigaction action = {.sa_handler = handler};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, 0) == 0);
    int fd = eventfd(0, 0);
    CHECK(fd >= 0);
    struct Operation operation = {.fd = fd};
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, operate, &operation) == 0);
    sleeping(&operation);
    CHECK(pthread_kill(thread, SIGUSR1) == 0 && pthread_join(thread, 0) == 0);
    CHECK(operation.result == -1 && operation.error == EINTR && signals == 1);
    action.sa_flags = SA_RESTART;
    CHECK(sigaction(SIGUSR1, &action, 0) == 0);
    operation = (struct Operation){.fd = fd};
    CHECK(pthread_create(&thread, 0, operate, &operation) == 0);
    sleeping(&operation);
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    while (signals != 2)
        sched_yield();
    sleeping(&operation);
    put(fd, 11);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == 8 && operation.output == 11);
    CHECK(close(fd) == 0);
    puts("EVENTFD_GROUP_PASS interruption");
}

static void inheritance(const char* program) {
    int inherited = eventfd(3, EFD_NONBLOCK), closed = eventfd(7, EFD_CLOEXEC | EFD_NONBLOCK);
    CHECK(inherited >= 0 && closed >= 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char a[24], b[24];
        snprintf(a, sizeof(a), "%d", inherited);
        snprintf(b, sizeof(b), "%d", closed);
        const char* loader = getenv("EVENTFD_EXEC_LOADER");
        if (loader)
            execl(loader, loader, program, "--exec-child", a, b, (char*)0);
        else
            execl(program, program, "--exec-child", a, b, (char*)0);
        CHECK(0 && "eventfd fixture exec failed");
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(take(inherited) == 5 && take(closed) == 7 && close(inherited) == 0 && close(closed) == 0);
    puts("EVENTFD_GROUP_PASS inheritance");
}

int main(int argc, char** argv) {
    setvbuf(stdout, 0, _IONBF, 0);
    if (argc == 4 && !strcmp(argv[1], "--exec-child")) {
        int inherited = atoi(argv[2]), closed = atoi(argv[3]);
        CHECK(fcntl(closed, F_GETFD) == -1 && errno == EBADF && take(inherited) == 3);
        put(inherited, 5);
        return 0;
    }
    CHECK(argc == 2 &&
          (!strcmp(argv[1], "--strict-writes") || !strcmp(argv[1], "--observe-native")));
    if (!geteuid())
        CHECK(setgroups(0, 0) == 0 && setgid(60011) == 0 && setuid(60011) == 0);
    CHECK(getuid() != 0 && geteuid() != 0);
    printf("EVENTFD_BEGIN uid=%u strict=%d\n", (unsigned)getuid(),
           !strcmp(argv[1], "--strict-writes"));
    creation();
    counters(!strcmp(argv[1], "--strict-writes"));
    faults_and_vectors();
    readiness();
    retained_io();
    interruption();
    inheritance(argv[0]);
    puts("EVENTFD_PASS groups=7");
    return 0;
}

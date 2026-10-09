// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef IO_LINKAGE
#define IO_LINKAGE "static"
#endif
#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "THREAD_IO_FAIL line=%d: %s errno=%d\n", __LINE__, #expr, errno);      \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

enum Kind { READ, READV, RECV, RECVMSG, WRITE, WRITEV, SEND, SENDMSG, ACCEPT, ACCEPT4 };

static int guest;

struct Operation {
    int fd, error;
    enum Kind kind;
    char bytes[5];
    struct iovec vectors[2];
    struct msghdr message;
    void* buffer;
    ssize_t result;
    uint64_t began, finished;
    atomic_int entered, done;
};

static void prepare(struct Operation* operation, int fd, enum Kind kind) {
    memset(operation, 0, sizeof(*operation));
    operation->fd = fd;
    operation->kind = kind;
    operation->buffer = operation->bytes;
    memcpy(operation->bytes, kind >= WRITE ? "right" : ".....", 5);
    operation->vectors[0] = (struct iovec){operation->bytes, 2};
    operation->vectors[1] = (struct iovec){operation->bytes + 2, 3};
    operation->message.msg_iov = operation->vectors;
    operation->message.msg_iovlen = 2;
}

static void* io_worker(void* pointer) {
    struct Operation* operation = pointer;
    atomic_store(&operation->entered, 1);
    switch (operation->kind) {
    case READ:
        operation->result = read(operation->fd, operation->buffer, 5);
        break;
    case READV:
        operation->result = readv(operation->fd, operation->vectors, 2);
        break;
    case RECV:
        operation->result = recv(operation->fd, operation->bytes, 5, 0);
        break;
    case RECVMSG:
        operation->result = recvmsg(operation->fd, &operation->message, 0);
        break;
    case WRITE:
        operation->result = write(operation->fd, operation->bytes, 5);
        break;
    case WRITEV:
        operation->result = writev(operation->fd, operation->vectors, 2);
        break;
    case SEND:
        operation->result = send(operation->fd, operation->bytes, 5, MSG_NOSIGNAL);
        break;
    case SENDMSG:
        operation->result = sendmsg(operation->fd, &operation->message, MSG_NOSIGNAL);
        break;
    case ACCEPT:
        operation->result = accept(operation->fd, 0, 0);
        break;
    case ACCEPT4:
        operation->result = accept4(operation->fd, 0, 0, SOCK_CLOEXEC | SOCK_NONBLOCK);
        break;
    }
    operation->error = errno;
    atomic_store(&operation->done, 1);
    return 0;
}

static void await_entry(struct Operation* operation) {
    while (!atomic_load(&operation->entered))
        sched_yield();
    // Two timer periods allow the worker to reach its actual blocking syscall.
    usleep(40000);
    CHECK(!atomic_load(&operation->done));
}

static void pair(int endpoints[2], int socket) {
    CHECK((socket ? socketpair(AF_UNIX, SOCK_STREAM, 0, endpoints) : pipe(endpoints)) == 0);
}

static void no_reader(int fd) {
    errno = 0;
    CHECK(write(fd, "x", 1) == -1 && errno == EPIPE);
}

static void blocked_receive(int socket, enum Kind kind, int replace_with_dup, int mutate_vectors) {
    int original[2], replacement[2];
    pair(original, socket);
    struct Operation operation;
    prepare(&operation, original[0], kind);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, io_worker, &operation) == 0);
    await_entry(&operation);
    if (!socket && kind == READ) {
        CHECK(execl("/__axiom64_io_missing__", "missing", (char*)0) == -1 && errno == ENOENT);
        char path[64];
        snprintf(path, sizeof(path), "/tmp/axiom-io-exec-%u", (unsigned)getpid());
        int file = open(path, O_WRONLY | O_CREAT | O_EXCL, 0700);
        CHECK(file >= 0 && write(file, "bad", 3) == 3 && close(file) == 0);
        CHECK(execl(path, path, (char*)0) == -1 && errno == ENOEXEC);
        CHECK(unlink(path) == 0 && !atomic_load(&operation.done));
    }
    if (replace_with_dup) {
        pair(replacement, socket);
        CHECK(dup2(replacement[0], operation.fd) == operation.fd);
        CHECK(close(replacement[0]) == 0);
        replacement[0] = operation.fd;
    } else {
        CHECK(close(original[0]) == 0);
        pair(replacement, socket);
        CHECK(replacement[0] == operation.fd);
    }
    char changed[5] = ".....";
    if (mutate_vectors) {
        operation.vectors[0] = (struct iovec){changed, 2};
        operation.vectors[1] = (struct iovec){changed + 2, 3};
    }
    CHECK(write(replacement[1], "wrong", 5) == 5);
    usleep(40000);
    CHECK(!atomic_load(&operation.done));
    CHECK(write(original[1], "right", 5) == 5);
    CHECK(pthread_join(thread, 0) == 0);
    CHECK(operation.result == 5 && !memcmp(operation.bytes, "right", 5));
    CHECK(!memcmp(changed, ".....", 5));
    no_reader(original[1]);
    char bytes[5];
    CHECK(read(replacement[0], bytes, 5) == 5 && !memcmp(bytes, "wrong", 5));
    CHECK(close(original[1]) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
}

static size_t fill(int fd) {
    int flags = fcntl(fd, F_GETFL);
    CHECK(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    char bytes[4096];
    memset(bytes, 'f', sizeof(bytes));
    size_t total = 0;
    for (;;) {
        ssize_t count = write(fd, bytes, sizeof(bytes));
        if (count == -1) {
            CHECK(errno == EAGAIN);
            break;
        }
        CHECK(count > 0);
        total += count;
        CHECK(total <= 16 * 1024 * 1024);
    }
    CHECK(fcntl(fd, F_SETFL, flags) == 0);
    return total;
}

static void drain(int fd, size_t total) {
    char bytes[4096];
    while (total) {
        size_t requested = total < sizeof(bytes) ? total : sizeof(bytes);
        ssize_t count = read(fd, bytes, requested);
        CHECK(count > 0 && (size_t)count <= requested);
        for (ssize_t i = 0; i < count; i++)
            CHECK(bytes[i] == 'f');
        total -= count;
    }
}

static void blocked_send(int socket, enum Kind kind, int mutate_vectors) {
    int original[2], replacement[2];
    pair(original, socket);
    int writer = socket ? 0 : 1, reader = 1 - writer;
    size_t filled = fill(original[writer]);
    struct Operation operation;
    prepare(&operation, original[writer], kind);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, io_worker, &operation) == 0);
    await_entry(&operation);
    pair(replacement, socket);
    CHECK(dup2(replacement[writer], operation.fd) == operation.fd);
    CHECK(close(replacement[writer]) == 0);
    replacement[writer] = operation.fd;
    char changed[5] = "wrong";
    if (mutate_vectors) {
        operation.vectors[0] = (struct iovec){changed, 2};
        operation.vectors[1] = (struct iovec){changed + 2, 3};
    }
    usleep(40000);
    CHECK(!atomic_load(&operation.done));
    drain(original[reader], filled);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == 5);
    char bytes[5];
    CHECK(read(original[reader], bytes, 5) == 5 && !memcmp(bytes, "right", 5));
    CHECK(read(original[reader], bytes, 1) == 0);
    int flags = fcntl(replacement[reader], F_GETFL);
    CHECK(fcntl(replacement[reader], F_SETFL, flags | O_NONBLOCK) == 0);
    CHECK(read(replacement[reader], bytes, 1) == -1 && errno == EAGAIN);
    CHECK(close(original[reader]) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
}

static volatile sig_atomic_t first_entered, second_entered, first_result, second_result;
static volatile sig_atomic_t first_byte, second_byte;
static int handler_pipe[2][2];

static void first_handler(int signal) {
    (void)signal;
    first_entered = 1;
    char byte = 0;
    first_result = read(handler_pipe[0][0], &byte, 1);
    first_byte = byte;
}

static void second_handler(int signal) {
    (void)signal;
    second_entered = 1;
    char byte = 0;
    second_result = read(handler_pipe[1][0], &byte, 1);
    second_byte = byte;
}

static void install_handler(int signal, void (*handler)(int), int restart) {
    struct sigaction action = {.sa_handler = handler, .sa_flags = restart ? SA_RESTART : 0};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(signal, &action, 0) == 0);
}

static void signal_restart(int restart, int nested) {
    CHECK(pipe(handler_pipe[0]) == 0 && pipe(handler_pipe[1]) == 0);
    first_entered = second_entered = first_result = second_result = first_byte = second_byte = 0;
    install_handler(SIGUSR1, first_handler, restart);
    install_handler(SIGUSR2, second_handler, 1);
    int original[2], replacement[2];
    CHECK(pipe(original) == 0);
    struct Operation operation;
    prepare(&operation, original[0], READ);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, io_worker, &operation) == 0);
    await_entry(&operation);
    CHECK(close(original[0]) == 0 && pipe(replacement) == 0 && replacement[0] == operation.fd);
    CHECK(write(replacement[1], "newer", 5) == 5);
    usleep(40000);
    CHECK(!atomic_load(&operation.done));
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    while (!first_entered)
        usleep(10000);
    usleep(40000);
    no_reader(original[1]); // The interrupted attempt releases its reference before the handler.
    if (nested) {
        CHECK(pthread_kill(thread, SIGUSR2) == 0);
        while (!second_entered)
            usleep(10000);
        usleep(40000);
        CHECK(write(handler_pipe[1][1], "2", 1) == 1);
    }
    CHECK(write(handler_pipe[0][1], "1", 1) == 1);
    CHECK(pthread_join(thread, 0) == 0);
    CHECK(first_result == 1 && first_byte == '1');
    if (nested)
        CHECK(second_result == 1 && second_byte == '2');
    if (restart)
        CHECK(operation.result == 5 && !memcmp(operation.bytes, "newer", 5));
    else
        CHECK(operation.result == -1 && operation.error == EINTR);
    CHECK(close(original[1]) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
    for (int i = 0; i < 2; i++)
        CHECK(close(handler_pipe[i][0]) == 0 && close(handler_pipe[i][1]) == 0);
}

static void listener_reuse(enum Kind kind) {
    static unsigned sequence;
    struct sockaddr address = {.sa_family = AF_UNIX};
    snprintf(address.sa_data + 1, sizeof(address.sa_data) - 1, "i%u.%u", (unsigned)getpid(),
             ++sequence);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0 && bind(listener, &address, sizeof(address)) == 0 &&
          listen(listener, 4) == 0);
    CHECK(accept4(listener, 0, 0, 0x100000) == -1 && errno == EINVAL);
    struct Operation operation;
    prepare(&operation, listener, kind);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, io_worker, &operation) == 0);
    await_entry(&operation);
    CHECK(close(listener) == 0);
    int replacement = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(replacement == listener);
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(client >= 0 && connect(client, &address, sizeof(address)) == 0);
    CHECK(pthread_join(thread, 0) == 0 && operation.result >= 0);
    int accepted = operation.result;
    if (kind == ACCEPT4) {
        CHECK((fcntl(accepted, F_GETFL) & O_NONBLOCK) != 0);
        CHECK((fcntl(accepted, F_GETFD) & FD_CLOEXEC) != 0);
    }
    CHECK(write(client, "right", 5) == 5);
    char bytes[5];
    CHECK(read(accepted, bytes, 5) == 5 && !memcmp(bytes, "right", 5));
    CHECK(close(client) == 0 && close(accepted) == 0 && close(replacement) == 0);
    client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(client >= 0 && connect(client, &address, sizeof(address)) == -1 && errno == ECONNREFUSED);
    CHECK(close(client) == 0);
}

static void partial_and_errors(void) {
    for (int socket = 0; socket < 2; socket++) {
        int endpoints[2];
        pair(endpoints, socket);
        CHECK(write(endpoints[1], "ri", 2) == 2);
        char bytes[5] = ".....";
        struct iovec vectors[] = {{bytes, 2}, {bytes + 2, 3}};
        CHECK(readv(endpoints[0], vectors, 2) == 2 && !memcmp(bytes, "ri...", 5));
        int flags = fcntl(endpoints[0], F_GETFL);
        CHECK(fcntl(endpoints[0], F_SETFL, flags | O_NONBLOCK) == 0);
        CHECK(read(endpoints[0], bytes, 1) == -1 && errno == EAGAIN);
        CHECK(fcntl(endpoints[0], F_SETFL, flags) == 0);
        if (socket) {
            CHECK(recv(endpoints[0], bytes, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
            if (guest) {
                CHECK(recv(endpoints[0], bytes, 1, MSG_WAITALL) == -1 && errno == EOPNOTSUPP);
                struct sockaddr address = {.sa_family = AF_UNIX};
                struct msghdr named = {.msg_name = &address,
                                       .msg_namelen = sizeof(address),
                                       .msg_iov = vectors,
                                       .msg_iovlen = 2};
                CHECK(recvmsg(endpoints[0], &named, 0) == -1 && errno == EOPNOTSUPP);
            }
            CHECK(write(endpoints[1], "right", 5) == 5);
            struct msghdr message = {.msg_iov = vectors, .msg_iovlen = 2};
            CHECK(recvmsg(endpoints[0], &message, MSG_PEEK) == 5 && !memcmp(bytes, "right", 5));
            CHECK(recv(endpoints[0], bytes, 5, 0) == 5 && !memcmp(bytes, "right", 5));
        } else {
            CHECK(pread(endpoints[0], bytes, 1, 0) == -1 && errno == ESPIPE);
            CHECK(pwrite(endpoints[1], bytes, 1, 0) == -1 && errno == ESPIPE);
        }
        CHECK(readv(endpoints[0], vectors, 1025) == -1 && errno == EINVAL);
        CHECK(close(endpoints[0]) == 0 && close(endpoints[1]) == 0);
    }
    CHECK(read(-1, 0, 0) == -1 && errno == EBADF);
    CHECK(recv(-1, 0, 0, 0) == -1 && errno == EBADF);
    int endpoints[2];
    CHECK(pipe(endpoints) == 0);
    void* mapping = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    struct Operation operation;
    prepare(&operation, endpoints[0], READ);
    operation.buffer = mapping;
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, io_worker, &operation) == 0);
    await_entry(&operation);
    CHECK(munmap(mapping, 4096) == 0 && write(endpoints[1], "right", 5) == 5);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == -1 && operation.error == EFAULT);
    CHECK(close(endpoints[0]) == 0 && close(endpoints[1]) == 0);
}

static void stopped_restart(void) {
    int original[2], ready[2];
    CHECK(pipe(original) == 0 && pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(original[1]) == 0 && close(ready[0]) == 0);
        struct Operation operation;
        prepare(&operation, original[0], READ);
        pthread_t thread;
        CHECK(pthread_create(&thread, 0, io_worker, &operation) == 0);
        await_entry(&operation);
        int replacement[2];
        CHECK(close(original[0]) == 0 && pipe(replacement) == 0 && replacement[0] == operation.fd);
        CHECK(write(replacement[1], "newer", 5) == 5 && write(ready[1], "r", 1) == 1);
        CHECK(pthread_join(thread, 0) == 0);
        CHECK(operation.result == 5 && !memcmp(operation.bytes, "newer", 5));
        _exit(0);
    }
    CHECK(close(original[0]) == 0 && close(ready[1]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    CHECK(kill(child, SIGSTOP) == 0);
    int status;
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    no_reader(original[1]);
    CHECK(kill(child, SIGCONT) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(original[1]) == 0 && close(ready[0]) == 0);
}

static void teardown(const char* executable, int execute, int writing) {
    int endpoints[2];
    CHECK(pipe(endpoints) == 0);
    size_t filled = writing ? fill(endpoints[1]) : 0;
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        int fd = endpoints[writing ? 1 : 0];
        CHECK(close(endpoints[writing ? 0 : 1]) == 0);
        struct Operation operation;
        prepare(&operation, fd, writing ? WRITE : READ);
        pthread_t thread;
        CHECK(pthread_create(&thread, 0, io_worker, &operation) == 0);
        await_entry(&operation);
        CHECK(close(fd) == 0);
        if (execute == -1) {
            CHECK(kill(getpid(), SIGKILL) == 0);
            CHECK(0);
        }
        if (execute == 1) {
            execl(executable, executable, "--exec-marker", (char*)0);
            CHECK(0);
        }
        _exit(23);
    }
    CHECK(close(endpoints[writing ? 1 : 0]) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    if (execute == -1)
        CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    else
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == (execute ? 0 : 23));
    int fd = endpoints[writing ? 0 : 1];
    if (writing) {
        drain(fd, filled);
        char byte;
        CHECK(read(fd, &byte, 1) == 0);
    } else
        no_reader(fd);
    CHECK(close(fd) == 0);
}

static sigjmp_buf abandoned_context;

static void abandon_handler(int signal) {
    (void)signal;
    siglongjmp(abandoned_context, 1);
}

static void* abandon_worker(void* pointer) {
    struct Operation* operation = pointer;
    if (!sigsetjmp(abandoned_context, 1)) {
        atomic_store(&operation->entered, 1);
        read(operation->fd, operation->bytes, 5);
        operation->result = -2;
    } else
        operation->result = read(operation->fd, operation->bytes, 5);
    atomic_store(&operation->done, 1);
    return 0;
}

static void abandoned_restart(void) {
    install_handler(SIGUSR1, abandon_handler, 1);
    int original[2], replacement[2];
    CHECK(pipe(original) == 0);
    struct Operation operation;
    prepare(&operation, original[0], READ);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, abandon_worker, &operation) == 0);
    await_entry(&operation);
    CHECK(close(original[0]) == 0 && pipe(replacement) == 0 && replacement[0] == operation.fd);
    CHECK(write(replacement[1], "newer", 5) == 5);
    CHECK(pthread_kill(thread, SIGUSR1) == 0 && pthread_join(thread, 0) == 0);
    CHECK(operation.result == 5 && !memcmp(operation.bytes, "newer", 5));
    no_reader(original[1]);
    CHECK(close(original[1]) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
}

static void* surviving_worker(void* pointer) {
    struct Operation* operation = pointer;
    io_worker(operation);
    CHECK(operation->result == 5 && !memcmp(operation->bytes, "right", 5));
    return 0;
}

static void leader_exit(void) {
    int original[2], ready[2];
    CHECK(pipe(original) == 0 && pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(original[1]) == 0 && close(ready[0]) == 0);
        struct Operation operation;
        prepare(&operation, original[0], READ);
        pthread_t thread;
        CHECK(pthread_create(&thread, 0, surviving_worker, &operation) == 0);
        await_entry(&operation);
        CHECK(close(original[0]) == 0 && write(ready[1], "r", 1) == 1);
        syscall(SYS_exit, 23);
        CHECK(0);
    }
    CHECK(close(original[0]) == 0 && close(ready[1]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    usleep(40000);
    CHECK(write(original[1], "right", 5) == 5);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    no_reader(original[1]);
    CHECK(close(original[1]) == 0 && close(ready[0]) == 0);
}

static void copied_files(void) {
    int original[2], ready[2];
    CHECK(pipe(original) == 0 && pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(original[1]) == 0 && close(ready[0]) == 0);
        char bytes[5];
        CHECK(write(ready[1], "r", 1) == 1);
        CHECK(read(original[0], bytes, 5) == 5 && !memcmp(bytes, "right", 5));
        _exit(0);
    }
    CHECK(close(ready[1]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    usleep(40000);
    int replacement[2];
    CHECK(close(original[0]) == 0 && pipe(replacement) == 0 && replacement[0] == original[0]);
    CHECK(write(replacement[1], "wrong", 5) == 5 && write(original[1], "right", 5) == 5);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    no_reader(original[1]);
    CHECK(close(original[1]) == 0 && close(ready[0]) == 0);
    CHECK(close(replacement[0]) == 0 && close(replacement[1]) == 0);
}

static uint64_t now_ms(void) {
    struct timespec value;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (uint64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static void* timed_worker(void* pointer) {
    struct Operation* operation = pointer;
    operation->began = now_ms();
    io_worker(pointer);
    operation->finished = now_ms();
    return 0;
}

enum { RCVTIMEO_OLD = 20, SNDTIMEO_OLD = 21, RCVTIMEO_NEW = 66, SNDTIMEO_NEW = 67 };

static void set_timeout(int fd, int option, unsigned milliseconds) {
    struct timeval value = {milliseconds / 1000, (milliseconds % 1000) * 1000};
    CHECK(setsockopt(fd, SOL_SOCKET, option, &value, sizeof(value)) == 0);
}

static struct timeval get_timeout(int fd, int option) {
    struct timeval value = {-1, -1};
    socklen_t length = sizeof(value);
    CHECK(getsockopt(fd, SOL_SOCKET, option, &value, &length) == 0);
    CHECK(length == sizeof(value));
    return value;
}

static void timeout_options(void) {
    int endpoints[2];
    pair(endpoints, 1);
    int options[] = {RCVTIMEO_OLD, SNDTIMEO_OLD, RCVTIMEO_NEW, SNDTIMEO_NEW};
    _Static_assert(sizeof(struct timeval) == 16, "Linux x86-64 timeval layout");
    for (unsigned i = 0; i < sizeof(options) / sizeof(options[0]); i++) {
        int option = options[i];
        struct timeval value = get_timeout(endpoints[0], option);
        CHECK(value.tv_sec == 0 && value.tv_usec == 0);
        value = (struct timeval){2, 30001};
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, option, &value, sizeof(value)) == 0);
        value = get_timeout(endpoints[0], option);
        CHECK(value.tv_sec == 2 && value.tv_usec >= 30001 && value.tv_usec <= 40000);
        char truncated[sizeof(value)];
        memset(truncated, 0x55, sizeof(truncated));
        socklen_t length = 5;
        CHECK(getsockopt(endpoints[0], SOL_SOCKET, option, truncated, &length) == 0);
        CHECK(length == 5 && !memcmp(truncated, &value, 5) && truncated[5] == 0x55);
        length = 0;
        CHECK(getsockopt(endpoints[0], SOL_SOCKET, option, 0, &length) == 0 && length == 0);
        length = (socklen_t)-1;
        CHECK(getsockopt(endpoints[0], SOL_SOCKET, option, &value, &length) == -1 &&
              errno == EINVAL);
        length = sizeof(value);
        CHECK(getsockopt(endpoints[0], SOL_SOCKET, option, 0, &length) == -1 && errno == EFAULT);
        CHECK(length == sizeof(value));
        CHECK(getsockopt(endpoints[0], SOL_SOCKET, option, &value, 0) == -1 && errno == EFAULT);
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, option, &value, 15) == -1 && errno == EINVAL);
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, option, &value, (socklen_t)-1) == -1 &&
              errno == EINVAL);
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, option, 0, sizeof(value)) == -1 &&
              errno == EFAULT);
        value = (struct timeval){0, -1};
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, option, &value, sizeof(value)) == -1 &&
              errno == EDOM);
        value.tv_usec = 1000000;
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, option, &value, sizeof(value)) == -1 &&
              errno == EDOM);
        value = get_timeout(endpoints[0], option);
        CHECK(value.tv_sec == 2 && value.tv_usec >= 30001 && value.tv_usec <= 40000);
        value = (struct timeval){-1, 0};
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, option, &value, sizeof(value)) == 0);
        value = get_timeout(endpoints[0], option);
        CHECK(value.tv_sec == 0 && value.tv_usec == 0);
        value = (struct timeval){INT64_MAX, 999999};
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, option, &value, sizeof(value)) == 0);
        value = get_timeout(endpoints[0], option);
        CHECK(value.tv_sec == 0 && value.tv_usec == 0);
        set_timeout(endpoints[0], option, 0);
    }
    int alias = dup(endpoints[0]);
    CHECK(alias >= 0);
    set_timeout(alias, RCVTIMEO_NEW, 120);
    struct timeval value = get_timeout(endpoints[0], RCVTIMEO_OLD);
    CHECK(value.tv_sec == 0 && value.tv_usec == 120000);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        set_timeout(alias, SNDTIMEO_OLD, 130);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    value = get_timeout(endpoints[0], SNDTIMEO_NEW);
    CHECK(value.tv_sec == 0 && value.tv_usec >= 130000 && value.tv_usec <= 140000);
    CHECK(close(alias) == 0 && close(endpoints[0]) == 0 && close(endpoints[1]) == 0);
    int pipes[2];
    CHECK(pipe(pipes) == 0);
    CHECK(setsockopt(pipes[0], SOL_SOCKET, RCVTIMEO_OLD, &value, sizeof(value)) == -1 &&
          errno == ENOTSOCK);
    CHECK(setsockopt(-1, SOL_SOCKET, RCVTIMEO_OLD, &value, sizeof(value)) == -1 && errno == EBADF);
    CHECK(setsockopt(-1, SOL_SOCKET, RCVTIMEO_OLD, &value, (socklen_t)-1) == -1 && errno == EBADF);
    CHECK(setsockopt(pipes[0], SOL_SOCKET, RCVTIMEO_OLD, &value, (socklen_t)-1) == -1 &&
          errno == ENOTSOCK);
    CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
}

static void timeout_reuse(enum Kind kind) {
    int original[2], replacement[2];
    pair(original, 1);
    int writing = kind >= WRITE;
    int option = writing ? SNDTIMEO_OLD : RCVTIMEO_OLD;
    set_timeout(original[0], option, 200);
    size_t filled = writing ? fill(original[0]) : 0;
    int alias = dup(original[0]);
    CHECK(alias >= 0);
    struct Operation operation;
    prepare(&operation, original[0], kind);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, timed_worker, &operation) == 0);
    await_entry(&operation);
    pair(replacement, 0);
    CHECK(dup2(replacement[writing], original[0]) == original[0]);
    CHECK(close(replacement[writing]) == 0);
    replacement[writing] = original[0];
    // The operation's deadline is captured once, even if an alias changes the option.
    set_timeout(alias, option, 10);
    CHECK(close(alias) == 0);
    if (!writing) {
        CHECK(write(replacement[1], "wrong", 5) == 5);
        char byte;
        CHECK(recv(original[1], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN);
    }
    CHECK(pthread_join(thread, 0) == 0);
    CHECK(operation.result == -1 && operation.error == EAGAIN);
    CHECK(operation.finished - operation.began >= 180 &&
          operation.finished - operation.began < 2000);
    char bytes[5];
    if (writing) {
        drain(original[1], filled);
        int flags = fcntl(replacement[0], F_GETFL);
        CHECK(fcntl(replacement[0], F_SETFL, flags | O_NONBLOCK) == 0);
        CHECK(read(replacement[0], bytes, 5) == -1 && errno == EAGAIN);
    } else {
        CHECK(!memcmp(operation.bytes, ".....", 5));
        CHECK(read(replacement[0], bytes, 5) == 5 && !memcmp(bytes, "wrong", 5));
    }
    CHECK(read(original[1], bytes, 1) == 0);
    CHECK(close(original[1]) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
}

static int timed_listener(struct sockaddr* address) {
    static unsigned sequence;
    *address = (struct sockaddr){.sa_family = AF_UNIX};
    snprintf(address->sa_data + 1, sizeof(address->sa_data) - 1, "t%u.%u", (unsigned)getpid(),
             ++sequence);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(fd >= 0 && bind(fd, address, sizeof(*address)) == 0 && listen(fd, 4) == 0);
    set_timeout(fd, RCVTIMEO_OLD, 200);
    return fd;
}

static void timeout_accept(enum Kind kind) {
    struct sockaddr address;
    int listener = timed_listener(&address);
    struct Operation operation;
    prepare(&operation, listener, kind);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, timed_worker, &operation) == 0);
    await_entry(&operation);
    CHECK(close(listener) == 0);
    int replacement[2];
    CHECK(pipe(replacement) == 0 && replacement[0] == listener);
    CHECK(write(replacement[1], "wrong", 5) == 5);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == -1 && operation.error == EAGAIN);
    CHECK(operation.finished - operation.began >= 180 &&
          operation.finished - operation.began < 2000);
    char bytes[5];
    CHECK(read(replacement[0], bytes, 5) == 5 && !memcmp(bytes, "wrong", 5));
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(client >= 0 && connect(client, &address, sizeof(address)) == -1 && errno == ECONNREFUSED);
    CHECK(close(client) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
    listener = timed_listener(&address);
    client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(client >= 0 && connect(client, &address, sizeof(address)) == 0);
    int accepted = accept(listener, 0, 0);
    CHECK(accepted >= 0);
    struct timeval value = get_timeout(accepted, RCVTIMEO_OLD);
    CHECK(value.tv_sec == 0 && value.tv_usec == 0);
    CHECK(close(accepted) == 0 && close(client) == 0 && close(listener) == 0);
}

static void timeout_signal(enum Kind kind) {
    CHECK(pipe(handler_pipe[0]) == 0);
    first_entered = first_result = first_byte = 0;
    install_handler(SIGUSR1, first_handler, 1);
    int original[2], replacement[2];
    pair(original, 1);
    int writing = kind >= WRITE;
    set_timeout(original[0], writing ? SNDTIMEO_OLD : RCVTIMEO_OLD, 2000);
    size_t filled = writing ? fill(original[0]) : 0;
    struct Operation operation;
    prepare(&operation, original[0], kind);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, timed_worker, &operation) == 0);
    await_entry(&operation);
    pair(replacement, 0);
    CHECK(dup2(replacement[writing], original[0]) == original[0]);
    CHECK(close(replacement[writing]) == 0);
    replacement[writing] = original[0];
    if (!writing)
        CHECK(write(replacement[1], "wrong", 5) == 5);
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    while (!first_entered)
        usleep(10000);
    usleep(40000);
    if (writing)
        drain(original[1], filled);
    char bytes[5];
    CHECK(recv(original[1], bytes, 1, MSG_DONTWAIT) == 0);
    CHECK(write(handler_pipe[0][1], "H", 1) == 1);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == -1 && operation.error == EINTR);
    CHECK(first_result == 1 && first_byte == 'H');
    if (writing) {
        int flags = fcntl(replacement[0], F_GETFL);
        CHECK(fcntl(replacement[0], F_SETFL, flags | O_NONBLOCK) == 0);
        CHECK(read(replacement[0], bytes, 5) == -1 && errno == EAGAIN);
    } else
        CHECK(read(replacement[0], bytes, 5) == 5 && !memcmp(bytes, "wrong", 5));
    CHECK(close(original[1]) == 0 && close(replacement[0]) == 0 && close(replacement[1]) == 0);
    CHECK(close(handler_pipe[0][0]) == 0 && close(handler_pipe[0][1]) == 0);
}

static void timeout_stop(void) {
    int original[2], ready[2];
    pair(original, 1);
    CHECK(pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(original[1]) == 0 && close(ready[0]) == 0);
        set_timeout(original[0], RCVTIMEO_OLD, 2000);
        struct Operation operation;
        prepare(&operation, original[0], READ);
        pthread_t thread;
        CHECK(pthread_create(&thread, 0, timed_worker, &operation) == 0);
        await_entry(&operation);
        int replacement[2];
        CHECK(close(original[0]) == 0 && pipe(replacement) == 0 && replacement[0] == operation.fd);
        CHECK(write(replacement[1], "wrong", 5) == 5 && write(ready[1], "r", 1) == 1);
        CHECK(pthread_join(thread, 0) == 0 && operation.result == -1 && operation.error == EINTR);
        char bytes[5];
        CHECK(read(replacement[0], bytes, 5) == 5 && !memcmp(bytes, "wrong", 5));
        _exit(0);
    }
    CHECK(close(original[0]) == 0 && close(ready[1]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && kill(child, SIGSTOP) == 0);
    int status;
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    CHECK(recv(original[1], &byte, 1, MSG_DONTWAIT) == 0);
    CHECK(kill(child, SIGCONT) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(original[1]) == 0 && close(ready[0]) == 0);
}

static void timeout_progress(void) {
    int endpoints[2];
    pair(endpoints, 1);
    set_timeout(endpoints[0], RCVTIMEO_OLD, 200);
    struct Operation operation;
    prepare(&operation, endpoints[0], RECVMSG);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, timed_worker, &operation) == 0);
    await_entry(&operation);
    CHECK(write(endpoints[1], "ri", 2) == 2);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == 2 &&
          !memcmp(operation.bytes, "ri...", 5));
    set_timeout(endpoints[0], SNDTIMEO_OLD, 100);
    static char payload[1024 * 1024];
    memset(payload, 'p', sizeof(payload));
    ssize_t sent = send(endpoints[0], payload, sizeof(payload), MSG_NOSIGNAL);
    CHECK(sent > 0 && (size_t)sent < sizeof(payload));
    size_t remaining = sent;
    char bytes[4096];
    while (remaining) {
        ssize_t count =
            read(endpoints[1], bytes, remaining < sizeof(bytes) ? remaining : sizeof(bytes));
        CHECK(count > 0 && (size_t)count <= remaining);
        for (ssize_t i = 0; i < count; i++)
            CHECK(bytes[i] == 'p');
        remaining -= count;
    }
    set_timeout(endpoints[0], RCVTIMEO_OLD, 1000);
    int flags = fcntl(endpoints[0], F_GETFL);
    CHECK(fcntl(endpoints[0], F_SETFL, flags | O_NONBLOCK) == 0);
    uint64_t began = now_ms();
    CHECK(read(endpoints[0], bytes, 1) == -1 && errno == EAGAIN && now_ms() - began < 500);
    CHECK(fcntl(endpoints[0], F_SETFL, flags) == 0);
    began = now_ms();
    CHECK(recv(endpoints[0], bytes, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN &&
          now_ms() - began < 500);
    struct pollfd poller = {endpoints[0], POLLIN, 0};
    began = now_ms();
    CHECK(poll(&poller, 1, 30) == 0 && now_ms() - began < 500);
    set_timeout(endpoints[0], RCVTIMEO_OLD, 0);
    prepare(&operation, endpoints[0], READ);
    CHECK(pthread_create(&thread, 0, timed_worker, &operation) == 0);
    await_entry(&operation);
    CHECK(write(endpoints[1], "right", 5) == 5);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == 5 &&
          !memcmp(operation.bytes, "right", 5));
    struct timeval negative = {-1, 0};
    CHECK(setsockopt(endpoints[0], SOL_SOCKET, RCVTIMEO_OLD, &negative, sizeof(negative)) == 0);
    began = now_ms();
    CHECK(read(endpoints[0], bytes, 1) == -1 && errno == EAGAIN && now_ms() - began < 500);
    CHECK(write(endpoints[1], "r", 1) == 1 && read(endpoints[0], bytes, 1) == 1 && bytes[0] == 'r');
    CHECK(close(endpoints[0]) == 0 && close(endpoints[1]) == 0);
}

static unsigned timeout_family(int family, int type, int protocol) {
    int fd = socket(family, type, protocol);
    if (!guest && fd < 0 && (errno == EPERM || errno == EACCES)) {
        printf("THREAD_IO_TIMEOUT_PRIVILEGED_SKIP family=%d type=%d\n", family, type);
        return 0;
    }
    CHECK(fd >= 0);
    if (family == AF_INET && type == SOCK_DGRAM) {
        struct sockaddr_in address = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        CHECK(bind(fd, (struct sockaddr*)&address, sizeof(address)) == 0);
    }
    if (family == AF_NETLINK) {
        struct {
            sa_family_t family;
            uint16_t padding;
            uint32_t pid, groups;
        } address = {AF_NETLINK, 0, 0, 0};

        CHECK(bind(fd, (struct sockaddr*)&address, sizeof(address)) == 0);
    }
    set_timeout(fd, RCVTIMEO_NEW, 150);
    set_timeout(fd, SNDTIMEO_NEW, 150);
    struct timeval value = get_timeout(fd, RCVTIMEO_OLD);
    CHECK(value.tv_sec == 0 && value.tv_usec >= 150000 && value.tv_usec <= 160000);
    struct Operation operation;
    prepare(&operation, fd, RECV);
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, timed_worker, &operation) == 0);
    await_entry(&operation);
    CHECK(close(fd) == 0);
    int replacement[2];
    CHECK(pipe(replacement) == 0 && replacement[0] == fd);
    CHECK(write(replacement[1], "wrong", 5) == 5);
    CHECK(pthread_join(thread, 0) == 0 && operation.result == -1 && operation.error == EAGAIN);
    CHECK(operation.finished - operation.began >= 130 &&
          operation.finished - operation.began < 2000);
    char bytes[5];
    CHECK(read(replacement[0], bytes, 5) == 5 && !memcmp(bytes, "wrong", 5));
    CHECK(close(replacement[0]) == 0 && close(replacement[1]) == 0);
    fd = socket(family, type, protocol);
    CHECK(fd >= 0);
    value = get_timeout(fd, RCVTIMEO_OLD);
    CHECK(value.tv_sec == 0 && value.tv_usec == 0);
    CHECK(close(fd) == 0);
    return 1;
}

static void socket_timeouts(void) {
    timeout_options();

    enum Kind kinds[] = {READ, READV, RECV, RECVMSG, WRITE, WRITEV, SEND, SENDMSG};

    for (unsigned i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++)
        timeout_reuse(kinds[i]);
    timeout_accept(ACCEPT);
    timeout_accept(ACCEPT4);
    timeout_signal(READ);
    timeout_signal(RECVMSG);
    timeout_signal(WRITE);
    timeout_signal(SENDMSG);
    timeout_stop();
    timeout_progress();
    unsigned families = timeout_family(AF_INET, SOCK_DGRAM, 0);
    families += timeout_family(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    families += timeout_family(AF_NETLINK, SOCK_RAW, 0);
    families += timeout_family(AF_PACKET, SOCK_RAW,
                               0); // Protocol zero never subscribes to ambient packets.
    for (int i = 0; i < 300; i++) {
        int endpoints[2];
        pair(endpoints, 1);
        struct timeval value = {0, 1};
        CHECK(setsockopt(endpoints[0], SOL_SOCKET, RCVTIMEO_OLD, &value, sizeof(value)) == 0);
        char byte;
        CHECK(read(endpoints[0], &byte, 1) == -1 && errno == EAGAIN);
        CHECK(close(endpoints[0]) == 0);
        CHECK(recv(endpoints[1], &byte, 1, MSG_DONTWAIT) == 0);
        CHECK(close(endpoints[1]) == 0);
    }
    CHECK(!guest || families == 4);
    printf("THREAD_IO_TIMEOUTS_PASS linkage=%s operations=10 signals=4 families=%u cycles=300\n",
           IO_LINKAGE, families);
}

int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "--exec-marker"))
        return 0;
    guest = argc == 2 && !strcmp(argv[1], "--guest");
    setvbuf(stdout, 0, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    socket_timeouts();
    if (argc == 2 && !strcmp(argv[1], "--timeout-only"))
        return 0;
    blocked_receive(0, READ, 0, 0); // Original close/reuse regression.
    blocked_receive(0, READV, 1, 1);
    blocked_receive(1, READ, 1, 0);
    blocked_receive(1, READV, 0, 1);
    blocked_receive(1, RECV, 0, 0);
    blocked_receive(1, RECVMSG, 1, 1);
    blocked_send(0, WRITE, 0);
    blocked_send(0, WRITEV, 1);
    blocked_send(1, WRITE, 0);
    blocked_send(1, WRITEV, 1);
    blocked_send(1, SEND, 0);
    blocked_send(1, SENDMSG, 1);
    printf("THREAD_IO_DESCRIPTIONS_PASS\n");
    signal_restart(0, 0);
    signal_restart(1, 0);
    signal_restart(1, 1);
    abandoned_restart();
    stopped_restart();
    printf("THREAD_IO_SIGNALS_PASS\n");
    listener_reuse(ACCEPT);
    listener_reuse(ACCEPT4);
    partial_and_errors();
    copied_files();
    printf("THREAD_IO_PATHS_PASS\n");
    for (int i = 0; i < 16; i++) {
        blocked_receive(i & 1, i & 1 ? RECVMSG : READV, i & 2, 1);
        teardown(argv[0], 0, i & 1);
    }
    teardown(argv[0], 1, 0);
    teardown(argv[0], 1, 1);
    teardown(argv[0], -1, 0);
    teardown(argv[0], -1, 1);
    leader_exit();
    printf("THREAD_IO_TEARDOWN_PASS\n");
    printf("THREAD_IO_TESTS_PASS linkage=%s\n", IO_LINKAGE);
    return 0;
}

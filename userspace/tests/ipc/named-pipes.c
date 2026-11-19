// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file
 * @brief Compares pipe and FIFO I/O, peer lifetime, and ext2 FIFO persistence.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c)                                                                                   \
    do {                                                                                           \
        if (!(c)) {                                                                                \
            printf("NAMED_PIPE_FAIL line=%d errno=%d %s\n", __LINE__, errno, #c);                  \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static void readiness(int at) {
    int status = openat(at, "queue", O_WRONLY | O_NONBLOCK);
    CHECK(status == -1 && errno == ENXIO);
    int reader = openat(at, "queue", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    CHECK(reader >= 0 && fcntl(reader, F_GETFD) == FD_CLOEXEC);
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u64 = 17};
    CHECK(epoll >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, reader, &event) == 0);

    struct pollfd watched = {.fd = reader, .events = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM};
    char byte = 0;
    CHECK(poll(&watched, 1, 0) == 0 && epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(read(reader, &byte, 1) == 0);
    CHECK(pread(reader, &byte, 1, 0) == -1 && errno == ESPIPE);
    CHECK(lseek(reader, 0, SEEK_CUR) == -1 && errno == ESPIPE);
    int writer = openat(at, "queue", O_WRONLY | O_NONBLOCK);
    CHECK(writer >= 0 && read(reader, &byte, 1) == -1 && errno == EAGAIN);
    CHECK(fsync(writer) == -1 && errno == EINVAL);
    int alias = dup(writer);
    CHECK(alias >= 0 && write(writer, "F", 1) == 1 && close(writer) == 0);
    CHECK(poll(&watched, 1, 0) == 1 && watched.revents == (POLLIN | POLLRDNORM));
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == EPOLLIN && event.data.u64 == 17);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(write(alias, "G", 1) == 1);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == EPOLLIN && event.data.u64 == 17);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    int count = -1;
    CHECK(ioctl(reader, FIONREAD, &count) == 0 && count == 2);
    CHECK(close(alias) == 0);
    CHECK(poll(&watched, 1, 0) == 1 && watched.revents == (POLLIN | POLLRDNORM | POLLHUP));
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == (EPOLLIN | EPOLLHUP));
    CHECK(read(reader, &byte, 1) == 1 && byte == 'F');
    CHECK(read(reader, &byte, 1) == 1 && byte == 'G' && read(reader, &byte, 1) == 0);
    CHECK(poll(&watched, 1, 0) == 1 && watched.revents == POLLHUP);

    writer = openat(at, "queue", O_WRONLY | O_NONBLOCK);
    CHECK(writer >= 0);
    CHECK(poll(&watched, 1, 0) == 0);
    CHECK(close(reader) == 0);
    watched.fd = writer;
    CHECK(poll(&watched, 1, 0) == 1 && watched.revents == (POLLOUT | POLLWRNORM | POLLERR));
    struct sigaction ignore = {.sa_handler = SIG_IGN}, saved;
    CHECK(sigemptyset(&ignore.sa_mask) == 0 && sigaction(SIGPIPE, &ignore, &saved) == 0);
    CHECK(write(writer, "x", 1) == -1 && errno == EPIPE);
    CHECK(sigaction(SIGPIPE, &saved, NULL) == 0);
    CHECK(close(writer) == 0 && close(epoll) == 0);
    puts("NAMED_PIPE_CASE readiness");
}

static void read_exact(int fd, char* data, size_t size) {
    while (size) {
        ssize_t count = read(fd, data, size);
        CHECK(count > 0);
        data += count;
        size -= (size_t)count;
    }
}

static size_t pipe_capacity(int reader, int writer) {
    char block[4096] = {0};
    CHECK(fcntl(writer, F_SETFL, O_NONBLOCK) == 0);
    size_t capacity = 0;
    while (write(writer, block, sizeof(block)) == (ssize_t)sizeof(block)) {
        capacity += sizeof(block);
        CHECK(capacity <= 1024 * 1024);
    }
    CHECK(errno == EAGAIN && capacity >= sizeof(block));
    for (size_t offset = 0; offset < capacity; offset += sizeof(block))
        read_exact(reader, block, sizeof(block));
    CHECK(fcntl(writer, F_SETFL, 0) == 0);
    return capacity;
}

static void wait_for_full(int reader, size_t capacity) {
    int available;
    do {
        CHECK(ioctl(reader, FIONREAD, &available) == 0);
        if ((size_t)available < capacity)
            usleep(1000);
    } while ((size_t)available < capacity);
    CHECK((size_t)available == capacity);
}

static void atomic_nonblocking_write(void) {
    int fds[2];
    CHECK(pipe(fds) == 0);
    size_t capacity = pipe_capacity(fds[0], fds[1]);
    char block[4096] = {0};
    for (size_t offset = 0; offset < capacity; offset += sizeof(block))
        CHECK(write(fds[1], block, sizeof(block)) == (ssize_t)sizeof(block));
    read_exact(fds[0], block, sizeof(block));
    CHECK(write(fds[1], "X", 1) == 1 && fcntl(fds[1], F_SETFL, O_NONBLOCK) == 0);
    struct iovec vectors[] = {{block, 2048}, {block + 2048, 2048}};
    CHECK(writev(fds[1], vectors, 2) == -1 && errno == EAGAIN);
    int queued = 0;
    CHECK(ioctl(fds[0], FIONREAD, &queued) == 0 && queued == (int)(capacity - sizeof(block) + 1));
    for (size_t offset = sizeof(block); offset < capacity; offset += sizeof(block))
        read_exact(fds[0], block, sizeof(block));
    char marker;
    CHECK(read(fds[0], &marker, 1) == 1 && marker == 'X');
    CHECK(writev(fds[1], vectors, 2) == (ssize_t)sizeof(block));
    read_exact(fds[0], block, sizeof(block));
    CHECK(close(fds[1]) == 0 && close(fds[0]) == 0);
}

static void capacity_and_readiness(int at) {
    int fds[2];
    if (at < 0) {
        CHECK(pipe2(fds, O_NONBLOCK) == 0);
    } else {
        fds[0] = openat(at, "queue", O_RDONLY | O_NONBLOCK);
        fds[1] = openat(at, "queue", O_WRONLY | O_NONBLOCK);
        CHECK(fds[0] >= 0 && fds[1] >= 0);
    }
    int original = fcntl(fds[0], F_GETPIPE_SZ);
    CHECK(original >= 4096 && fcntl(fds[1], F_GETPIPE_SZ) == original);
    CHECK(fcntl(fds[1], F_SETPIPE_SZ, 5000) == 8192 && fcntl(fds[0], F_GETPIPE_SZ) == 8192);
    CHECK(fcntl(fds[1], F_SETPIPE_SZ, -1) == -1 && errno == EINVAL);
    if (geteuid())
        CHECK(fcntl(fds[0], F_SETPIPE_SZ, 1024 * 1024 + 1) == -1 && errno == EPERM);
    int devnull = open("/dev/null", O_RDONLY);
    CHECK(devnull >= 0 && fcntl(devnull, F_GETPIPE_SZ) == -1 && errno == EBADF);
    CHECK(fcntl(devnull, F_SETPIPE_SZ, 4096) == -1 && errno == EBADF && close(devnull) == 0);

    char first[4096], second[4096], received[4096];
    memset(first, 'A', sizeof(first));
    memset(second, 'B', sizeof(second));
    CHECK(write(fds[1], first, sizeof(first)) == (ssize_t)sizeof(first));
    CHECK(write(fds[1], second, sizeof(second)) == (ssize_t)sizeof(second));
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLOUT | EPOLLET, .data.u64 = 12};
    struct pollfd writer = {.fd = fds[1], .events = POLLOUT};
    CHECK(epoll >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, fds[1], &event) == 0);
    CHECK(read(fds[0], received, 1) == 1 && received[0] == 'A');
    CHECK(write(fds[1], "X", 1) == -1 && errno == EAGAIN);
    CHECK(poll(&writer, 1, 0) == 0 && epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(fcntl(fds[0], F_SETPIPE_SZ, 4096) == -1 && errno == EBUSY);
    CHECK(fcntl(fds[0], F_GETPIPE_SZ) == 8192);
    read_exact(fds[0], received, sizeof(first) - 1);
    CHECK(memcmp(received, first, sizeof(first) - 1) == 0);
    CHECK(poll(&writer, 1, 0) == 1 && writer.revents == POLLOUT);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == EPOLLOUT && event.data.u64 == 12);
    CHECK(write(fds[1], "C", 1) == 1 && poll(&writer, 1, 0) == 0);
    // POLLOUT follows free page slots. An actual write can still merge into the tail.
    CHECK(write(fds[1], "D", 1) == 1 && epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(fcntl(fds[0], F_SETPIPE_SZ, 9000) == 16384);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == EPOLLOUT && event.data.u64 == 12);
    int available = 0;
    CHECK(ioctl(fds[0], FIONREAD, &available) == 0 && available == 4098);
    read_exact(fds[0], received, sizeof(second));
    CHECK(memcmp(received, second, sizeof(second)) == 0);
    CHECK(fcntl(fds[1], F_SETPIPE_SZ, 0) == 4096 && fcntl(fds[0], F_GETPIPE_SZ) == 4096);
    CHECK(poll(&writer, 1, 0) == 0);
    CHECK(read(fds[0], received, 2) == 2 && memcmp(received, "CD", 2) == 0);
    CHECK(close(epoll) == 0 && close(fds[1]) == 0 && close(fds[0]) == 0);
}

static void resize_wakes_writer(void) {
    int fds[2], status[2];
    CHECK(pipe(fds) == 0 && pipe(status) == 0);
    CHECK(fcntl(fds[0], F_SETPIPE_SZ, 4096) == 4096);
    char page[4096];
    memset(page, 'R', sizeof(page));
    CHECK(write(fds[1], page, sizeof(page)) == (ssize_t)sizeof(page));
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(fds[0]) == 0 && close(status[0]) == 0);
        CHECK(write(status[1], "B", 1) == 1 && write(fds[1], "W", 1) == 1);
        CHECK(write(status[1], "D", 1) == 1);
        _exit(0);
    }
    CHECK(close(fds[1]) == 0 && close(status[1]) == 0);
    char marker;
    CHECK(read(status[0], &marker, 1) == 1 && marker == 'B');
    struct pollfd waiting = {.fd = status[0], .events = POLLIN};
    CHECK(poll(&waiting, 1, 40) == 0);
    CHECK(fcntl(fds[0], F_SETPIPE_SZ, 8192) == 8192);
    CHECK(read(status[0], &marker, 1) == 1 && marker == 'D');
    int exited;
    CHECK(waitpid(child, &exited, 0) == child && WIFEXITED(exited) && WEXITSTATUS(exited) == 0);
    read_exact(fds[0], page, sizeof(page));
    for (size_t i = 0; i < sizeof(page); ++i)
        CHECK(page[i] == 'R');
    CHECK(read(fds[0], &marker, 1) == 1 && marker == 'W');
    CHECK(read(fds[0], &marker, 1) == 0 && close(fds[0]) == 0 && close(status[0]) == 0);
}

static void read_fault_after_head_slot(void) {
    int fds[2];
    CHECK(pipe(fds) == 0 && fcntl(fds[1], F_SETPIPE_SZ, 8192) == 8192);
    char page[4096];
    memset(page, 'X', sizeof(page));
    CHECK(write(fds[1], page, sizeof(page)) == (ssize_t)sizeof(page));
    memset(page, 'Y', sizeof(page));
    CHECK(write(fds[1], page, sizeof(page)) == (ssize_t)sizeof(page));
    read_exact(fds[0], page, sizeof(page) - 1);

    void* guard = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(guard != MAP_FAILED);
    char head;
    struct iovec vectors[] = {{&head, 1}, {guard, 4096}};
    CHECK(readv(fds[0], vectors, 2) == 1 && head == 'X');
    int queued = 0;
    CHECK(ioctl(fds[0], FIONREAD, &queued) == 0 && queued == (int)sizeof(page));
    read_exact(fds[0], page, sizeof(page));
    for (size_t i = 0; i < sizeof(page); ++i)
        CHECK(page[i] == 'Y');
    CHECK(munmap(guard, 4096) == 0 && close(fds[0]) == 0 && close(fds[1]) == 0);
}

struct pipe_writer {
    int fd;
    struct iovec vectors[3];
    ssize_t result;
};

static void* write_vectors(void* arg) {
    struct pipe_writer* writer = arg;
    writer->result = writev(writer->fd, writer->vectors, 3);
    return NULL;
}

static void open_pair(int at, int pipe_fds[2]) {
    if (at < 0) {
        CHECK(pipe(pipe_fds) == 0);
    } else {
        pipe_fds[0] = openat(at, "queue", O_RDONLY | O_NONBLOCK);
        pipe_fds[1] = openat(at, "queue", O_WRONLY);
        CHECK(pipe_fds[0] >= 0 && pipe_fds[1] >= 0 && fcntl(pipe_fds[0], F_SETFL, 0) == 0);
    }
}

static void retained_vector_write(int at) {
    int pipe_fds[2];
    open_pair(at, pipe_fds);
    size_t capacity = pipe_capacity(pipe_fds[0], pipe_fds[1]);
    size_t total = 2 * capacity + 4096;
    char* data = malloc(total);
    char* received = malloc(total);
    CHECK(data && received);
    for (size_t n = 0; n < total; n++)
        data[n] = (char)(n / 4096 + n * 31);
    struct pipe_writer writer = {
        .fd = pipe_fds[1],
        .vectors = {{data, 37}, {NULL, 0}, {data + 37, total - 37}},
    };
    int replacement[2];
    CHECK(pipe2(replacement, O_NONBLOCK) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, write_vectors, &writer) == 0);
    wait_for_full(pipe_fds[0], capacity);
    // The original descriptor and vectors must remain selected across the wait.
    writer.vectors[2] = (struct iovec){NULL, 1};
    CHECK(dup2(replacement[1], pipe_fds[1]) == pipe_fds[1]);
    read_exact(pipe_fds[0], received, total);
    CHECK(pthread_join(thread, NULL) == 0 && writer.result == (ssize_t)total);
    CHECK(memcmp(data, received, total) == 0);
    CHECK(read(pipe_fds[0], received, 1) == 0);
    CHECK(read(replacement[0], received, 1) == -1 && errno == EAGAIN);
    CHECK(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0);
    CHECK(close(replacement[0]) == 0 && close(replacement[1]) == 0);
    free(received);
    free(data);
}

static volatile sig_atomic_t write_signal;

static void note_write_signal(int signal_number) {
    write_signal = signal_number;
}

static void interrupted_partial_write(int signal_number, int at, const char* fifo_path) {
    int fds[2];
    open_pair(at, fds);
    size_t capacity = pipe_capacity(fds[0], fds[1]);
    int observer = -1, watch = -1;
    if (fifo_path) {
        observer = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        CHECK(observer >= 0 && (watch = inotify_add_watch(observer, fifo_path, IN_MODIFY)) >= 0);
    }
    char* data = malloc(2 * capacity);
    CHECK(data);
    memset(data, 'W', 2 * capacity);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(fds[0]) == 0);
        struct sigaction action = {.sa_handler = note_write_signal, .sa_flags = SA_RESTART};
        CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(signal_number, &action, NULL) == 0);
        CHECK(write(fds[1], data, 2 * capacity) == (ssize_t)capacity);
        CHECK(write_signal == signal_number);
        _exit(0);
    }
    CHECK(close(fds[1]) == 0);
    wait_for_full(fds[0], capacity);
    if (signal_number == SIGPIPE)
        CHECK(close(fds[0]) == 0);
    else
        CHECK(kill(child, signal_number) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    if (observer >= 0) {
        struct inotify_event event;
        CHECK(read(observer, &event, sizeof(event)) == (ssize_t)sizeof(event));
        CHECK(event.wd == watch && event.mask == IN_MODIFY && event.len == 0);
        CHECK(read(observer, &event, sizeof(event)) == -1 && errno == EAGAIN &&
              close(observer) == 0);
    }
    if (signal_number != SIGPIPE) {
        read_exact(fds[0], data, capacity);
        for (size_t n = 0; n < capacity; n++)
            CHECK(data[n] == 'W');
        CHECK(read(fds[0], data, 1) == 0 && close(fds[0]) == 0);
    }
    free(data);
}

static void rendezvous(int at) {
    int control[2], status;
    CHECK(pipe(control) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    char byte = 0;
    if (!child) {
        CHECK(close(control[0]) == 0 && write(control[1], "S", 1) == 1);
        int reader = openat(at, "queue", O_RDONLY);
        CHECK(reader >= 0 && write(control[1], "R", 1) == 1);
        CHECK(read(reader, &byte, 1) == 1 && byte == 'P');
        _exit(0);
    }
    CHECK(close(control[1]) == 0 && read(control[0], &byte, 1) == 1 && byte == 'S');
    CHECK(poll(&(struct pollfd){.fd = control[0], .events = POLLIN}, 1, 100) == 0);
    int writer = openat(at, "queue", O_WRONLY);
    CHECK(writer >= 0 && read(control[0], &byte, 1) == 1 && byte == 'R');
    CHECK(write(writer, "P", 1) == 1 && close(writer) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(control[0]) == 0);
    puts("NAMED_PIPE_CASE rendezvous");
}

static void peer_open_and_close(int at, int stop) {
    int control[2], status;
    CHECK(pipe(control) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    char byte = 0;
    if (!child) {
        CHECK(close(control[0]) == 0 && write(control[1], "B", 1) == 1);
        int reader = openat(at, "queue", O_RDONLY);
        CHECK(reader >= 0 && read(reader, &byte, 1) == 1 && byte == 'T');
        CHECK(read(reader, &byte, 1) == 0 && close(reader) == 0);
        _exit(0);
    }
    CHECK(close(control[1]) == 0 && read(control[0], &byte, 1) == 1 && byte == 'B');
    CHECK(poll(&(struct pollfd){.fd = control[0], .events = POLLIN}, 1, 100) == 0);
    if (stop) {
        CHECK(kill(child, SIGSTOP) == 0);
        CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
        CHECK(openat(at, "queue", O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
        CHECK(kill(child, SIGCONT) == 0);
    }
    int writer = openat(at, "queue", O_WRONLY | (stop ? 0 : O_NONBLOCK));
    CHECK(writer >= 0 && write(writer, "T", 1) == 1 && close(writer) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(control[0]) == 0);
}

static int report_signal = -1;

static void caught(int sig) {
    int saved = errno;
    if (sig == SIGUSR1 && write(report_signal, "I", 1) != 1)
        _exit(2);
    errno = saved;
}

static void interrupted_open(int at, int restart) {
    int control[2], status;
    CHECK(pipe(control) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    char byte = 0;
    if (!child) {
        CHECK(close(control[0]) == 0);
        report_signal = control[1];
        struct sigaction action = {.sa_handler = caught, .sa_flags = restart ? SA_RESTART : 0};
        CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, NULL) == 0);
        int expected_fd = openat(at, "queue", O_PATH);
        CHECK(expected_fd >= 0 && close(expected_fd) == 0);
        CHECK(write(control[1], "B", 1) == 1);
        int reader = openat(at, "queue", O_RDONLY);
        if (restart) {
            CHECK(reader == expected_fd && read(reader, &byte, 1) == 1 && byte == 'S');
            CHECK(close(reader) == 0);
        } else {
            CHECK(reader == -1 && errno == EINTR);
            reader = openat(at, "queue", O_PATH);
            CHECK(reader == expected_fd && close(reader) == 0);
        }
        _exit(0);
    }
    CHECK(close(control[1]) == 0 && read(control[0], &byte, 1) == 1 && byte == 'B');
    CHECK(poll(&(struct pollfd){.fd = control[0], .events = POLLIN}, 1, 100) == 0);
    CHECK(kill(child, SIGUSR1) == 0 && read(control[0], &byte, 1) == 1 && byte == 'I');
    int writer = -1;
    if (restart) {
        writer = openat(at, "queue", O_WRONLY);
        CHECK(writer >= 0 && write(writer, "S", 1) == 1 && close(writer) == 0);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(openat(at, "queue", O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
    CHECK(close(control[0]) == 0);
}

struct cancel_open {
    int directory, control;
};

static void* open_for_cancel(void* argument) {
    const struct cancel_open* args = argument;
    CHECK(write(args->control, "B", 1) == 1);
    int reader = openat(args->directory, "queue", O_RDONLY);
    if (reader >= 0)
        CHECK(close(reader) == 0);
    return NULL;
}

static void cancellation(int at) {
    int control[2];
    CHECK(pipe(control) == 0);
    struct cancel_open state = {.directory = at, .control = control[1]};
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, open_for_cancel, &state) == 0);
    char byte = 0;
    CHECK(read(control[0], &byte, 1) == 1 && byte == 'B');
    CHECK(poll(&(struct pollfd){.fd = control[0], .events = POLLIN}, 1, 100) == 0);
    CHECK(pthread_cancel(worker) == 0);
    void* result = NULL;
    CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(openat(at, "queue", O_WRONLY | O_NONBLOCK) == -1 && errno == ENXIO);
    CHECK(close(control[0]) == 0 && close(control[1]) == 0);
    puts("NAMED_PIPE_CASE interruption-cancellation");
}

static void aliases(int at) {
    CHECK(linkat(at, "queue", at, "alias", 0) == 0);
    struct stat primary, alias;
    CHECK(fstatat(at, "queue", &primary, 0) == 0 && fstatat(at, "alias", &alias, 0) == 0);
    CHECK(primary.st_ino == alias.st_ino && primary.st_nlink == 2 && alias.st_nlink == 2);
    int reader = openat(at, "queue", O_RDONLY | O_NONBLOCK);
    int writer = openat(at, "alias", O_WRONLY | O_NONBLOCK);
    char byte = 0;
    CHECK(reader >= 0 && writer >= 0 && write(writer, "A", 1) == 1);
    CHECK(read(reader, &byte, 1) == 1 && byte == 'A');
    CHECK(unlinkat(at, "alias", 0) == 0 && fstat(writer, &alias) == 0 && alias.st_nlink == 1);
    CHECK(close(writer) == 0 && close(reader) == 0);
    puts("NAMED_PIPE_CASE inode-aliases");
}

static void replace(int at) {
    int original = openat(at, "queue", O_RDWR | O_NONBLOCK);
    CHECK(original >= 0 && write(original, "O", 1) == 1);
    CHECK(unlinkat(at, "queue", 0) == 0);
    struct stat old, fresh;
    CHECK(fstat(original, &old) == 0 && S_ISFIFO(old.st_mode) && old.st_nlink == 0);
    CHECK(mkfifoat(at, "queue", 0600) == 0);
    int replacement = openat(at, "queue", O_RDWR | O_NONBLOCK);
    CHECK(replacement >= 0 && fstat(replacement, &fresh) == 0 && fresh.st_ino != old.st_ino);
    char byte = 0;
    CHECK(read(replacement, &byte, 1) == -1 && errno == EAGAIN);
    CHECK(write(replacement, "N", 1) == 1);
    CHECK(read(original, &byte, 1) == 1 && byte == 'O');
    CHECK(read(replacement, &byte, 1) == 1 && byte == 'N');
    CHECK(close(original) == 0 && close(replacement) == 0);
    puts("NAMED_PIPE_CASE unlink-recreate");
}

static void packet_pipes(void) {
    int fds[2];
    CHECK(pipe2(fds, O_DIRECT | O_NONBLOCK | O_CLOEXEC) == 0);
    int reader = fds[0], writer = fds[1];
    CHECK(fcntl(reader, F_GETFL) == (O_RDONLY | O_NONBLOCK));
    CHECK(fcntl(writer, F_GETFL) == (O_WRONLY | O_DIRECT | O_NONBLOCK));
    CHECK(fcntl(reader, F_GETFD) == FD_CLOEXEC && fcntl(writer, F_GETFD) == FD_CLOEXEC);
    int alias = dup(writer);
    CHECK(alias >= 0 && fcntl(alias, F_GETFD) == 0);
    CHECK(fcntl(alias, F_SETPIPE_SZ, 8192) == 8192);

    struct iovec parts[] = {{.iov_base = "ab", .iov_len = 2}, {.iov_base = "cd", .iov_len = 2}};
    CHECK(writev(alias, parts, 2) == 4);
    CHECK(write(writer, "XYZ", 3) == 3);
    CHECK(write(writer, "", 0) == 0);
    CHECK(write(writer, "!", 1) == -1 && errno == EAGAIN);
    CHECK(fcntl(writer, F_SETPIPE_SZ, 4096) == -1 && errno == EBUSY);
    struct pollfd writable = {.fd = writer, .events = POLLOUT};
    CHECK(poll(&writable, 1, 0) == 0);
    char buffer[8192];
    CHECK(read(reader, buffer, 0) == 0);
    CHECK(read(reader, buffer, 2) == 2 && memcmp(buffer, "ab", 2) == 0);
    int count = -1;
    CHECK(ioctl(reader, FIONREAD, &count) == 0 && count == 3);
    CHECK(poll(&writable, 1, 0) == 1 && writable.revents == POLLOUT);
    CHECK(fcntl(reader, F_SETPIPE_SZ, 4096) == 4096);
    CHECK(fcntl(reader, F_SETPIPE_SZ, 8192) == 8192);

    // The original packet survives a copy fault, and a following read stops at its boundary.
    void* inaccessible = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(inaccessible != MAP_FAILED);
    CHECK(syscall(SYS_read, reader, inaccessible, 2) == -1 && errno == EFAULT);
    CHECK(munmap(inaccessible, 4096) == 0);
    CHECK(fcntl(alias, F_SETFL, O_NONBLOCK) == 0 && !(fcntl(writer, F_GETFL) & O_DIRECT));
    CHECK(write(writer, "yz", 2) == 2);
    char first, rest[8];
    struct iovec reads[] = {{.iov_base = &first, .iov_len = 1},
                            {.iov_base = rest, .iov_len = sizeof(rest)}};
    CHECK(readv(reader, reads, 2) == 3 && first == 'X' && memcmp(rest, "YZ", 2) == 0);
    // Linux merges a leading remainder into an already queued stream slot after a mode change.
    CHECK(fcntl(alias, F_SETFL, O_NONBLOCK | O_DIRECT) == 0);
    CHECK((fcntl(writer, F_GETFL) & O_DIRECT) != 0);
    CHECK(write(writer, "q", 1) == 1);
    CHECK(read(reader, buffer, sizeof(buffer)) == 3 && memcmp(buffer, "yzq", 3) == 0);

    memset(buffer, 'x', 4096);
    memset(buffer + 4096, 'y', 9);
    CHECK(write(writer, buffer, 4105) == 4105);
    memset(buffer, 0, sizeof(buffer));
    CHECK(read(reader, buffer, sizeof(buffer)) == 4096 && buffer[0] == 'x' && buffer[4095] == 'x');
    CHECK(read(reader, buffer, sizeof(buffer)) == 9 && buffer[0] == 'y' && buffer[8] == 'y');
    CHECK(read(reader, buffer, sizeof(buffer)) == -1 && errno == EAGAIN);
    CHECK(close(alias) == 0 && close(writer) == 0);
    CHECK(read(reader, buffer, sizeof(buffer)) == 0 && close(reader) == 0);
    puts("NAMED_PIPE_CASE packet-mode");
}

static void packet_fifo(int at) {
    CHECK(openat(at, "queue", O_RDWR | O_NONBLOCK | O_DIRECT) == -1 && errno == EINVAL);
    int reader = openat(at, "queue", O_RDONLY | O_NONBLOCK);
    int writer = openat(at, "queue", O_WRONLY | O_NONBLOCK);
    CHECK(reader >= 0 && writer >= 0);
    CHECK(fcntl(writer, F_SETFL, O_NONBLOCK | O_DIRECT) == 0);
    CHECK(write(writer, "abc", 3) == 3 && write(writer, "d", 1) == 1);
    char bytes[8];
    CHECK(read(reader, bytes, 1) == 1 && bytes[0] == 'a');
    CHECK(read(reader, bytes, sizeof(bytes)) == 1 && bytes[0] == 'd');
    CHECK(read(reader, bytes, sizeof(bytes)) == -1 && errno == EAGAIN);
    CHECK(close(writer) == 0 && close(reader) == 0);
    puts("NAMED_PIPE_CASE fifo-packet-mode");
}

static void storage_test(int create) {
    const char* path = "/source/axiom-fifo-retained";
    const char* alias = "/source/axiom-fifo-alias";
    if (create) {
        umask(0);
        CHECK(mkfifo(path, 0640) == 0 && link(path, alias) == 0);
    }
    struct stat inode, linked;
    CHECK(stat(path, &inode) == 0 && stat(alias, &linked) == 0);
    CHECK(S_ISFIFO(inode.st_mode) && (inode.st_mode & 0777) == 0640);
    CHECK(inode.st_ino == linked.st_ino && inode.st_nlink == 2 && inode.st_size == 0);
    int reader = open(path, O_RDONLY | O_NONBLOCK);
    int writer = open(alias, O_WRONLY | O_NONBLOCK);
    CHECK(reader >= 0 && writer >= 0);
    char byte = 0;
    CHECK(read(reader, &byte, 1) == -1 && errno == EAGAIN);
    CHECK(write(writer, create ? "A" : "B", 1) == 1);
    if (!create)
        CHECK(read(reader, &byte, 1) == 1 && byte == 'B');
    CHECK(close(reader) == 0 && close(writer) == 0);
    sync();
    printf("NAMED_PIPE_STORAGE_PASS phase=%s inode=%lu\n", create ? "create" : "reopen",
           (unsigned long)inode.st_ino);
}

static const char pipe_max_size[] = "/proc/sys/fs/pipe-max-size";
static const char pipe_hard_pages[] = "/proc/sys/fs/pipe-user-pages-hard";
static const char pipe_soft_pages[] = "/proc/sys/fs/pipe-user-pages-soft";

static void read_limit(int fd, char value[32]) {
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    ssize_t count = read(fd, value, 31);
    CHECK(count > 0 && value[count - 1] == '\n');
    value[count] = 0;
    CHECK(read(fd, value + count, 1) == 0);
}

static void write_limit(int fd, const char* value, ssize_t accepted, const char* expected) {
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    CHECK(write(fd, value, strlen(value)) == accepted && (accepted >= 0 || errno == EINVAL));
    char actual[32];
    read_limit(fd, actual);
    CHECK(strcmp(actual, expected) == 0);
}

static void drop_to(uid_t uid) {
    CHECK(setgroups(0, NULL) == 0 && setgid(uid) == 0 && setuid(uid) == 0);
    CHECK(getuid() == uid && geteuid() == uid);
}

static void wait_success(pid_t pid) {
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void hard_quota(int max, const char* fifo) {
    int ready[2], resume[2];
    CHECK(pipe(ready) == 0 && pipe(resume) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        CHECK(close(ready[0]) == 0 && close(resume[1]) == 0);
        drop_to(55100);
        CHECK(open(pipe_max_size, O_WRONLY) == -1 && errno == EACCES);
        CHECK(write(max, "65536", 5) == -1 && errno == EPERM);
        int a[2], b[2] = {-1, -1};
        CHECK(pipe(a) == 0 && fcntl(a[0], F_GETPIPE_SZ) == 32768);
        CHECK(pipe(b) == -1 && errno == ENFILE && b[0] == -1 && b[1] == -1);
        CHECK(fcntl(a[0], F_SETPIPE_SZ, 65536) == -1 && errno == EPERM);
        CHECK(fcntl(a[0], F_SETPIPE_SZ, 16384) == 16384);
        CHECK(pipe(b) == 0 && fcntl(b[1], F_GETPIPE_SZ) == 32768);
        CHECK(fcntl(a[0], F_SETPIPE_SZ, 32768) == -1 && errno == EPERM);
        CHECK(open(fifo, O_RDWR | O_NONBLOCK) == -1 && errno == ENOMEM);
        CHECK(write(ready[1], "r", 1) == 1 && close(ready[1]) == 0);
        char ack;
        CHECK(read(resume[0], &ack, 1) == 1 && ack == 'g' && close(resume[0]) == 0);

        CHECK(close(b[0]) == 0 && close(b[1]) == 0);
        int named = open(fifo, O_RDWR | O_NONBLOCK);
        CHECK(named >= 0 && fcntl(named, F_GETPIPE_SZ) == 32768);
        CHECK(pipe(b) == -1 && errno == ENFILE);
        CHECK(close(named) == 0 && pipe(b) == 0);
        CHECK(close(b[0]) == 0 && close(b[1]) == 0);
        CHECK(close(a[0]) == 0 && close(a[1]) == 0);
        _exit(0);
    }
    CHECK(close(ready[1]) == 0 && close(resume[0]) == 0);
    char signal;
    CHECK(read(ready[0], &signal, 1) == 1 && signal == 'r' && close(ready[0]) == 0);
    pid_t other = fork();
    CHECK(other >= 0);
    if (other == 0) {
        CHECK(close(resume[1]) == 0);
        drop_to(55101);
        int fds[2];
        CHECK(pipe(fds) == 0 && fcntl(fds[0], F_GETPIPE_SZ) == 32768);
        CHECK(close(fds[0]) == 0 && close(fds[1]) == 0);
        _exit(0);
    }
    wait_success(other);
    CHECK(write(resume[1], "g", 1) == 1 && close(resume[1]) == 0);
    wait_success(child);
}

static void soft_quota(void) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        drop_to(55102);
        int a[2], b[2], c[2], d[2];
        CHECK(pipe(a) == 0 && fcntl(a[0], F_GETPIPE_SZ) == 32768);
        CHECK(pipe(b) == 0 && fcntl(b[0], F_GETPIPE_SZ) == 8192);
        CHECK(pipe(c) == 0 && fcntl(c[0], F_GETPIPE_SZ) == 8192);
        CHECK(pipe(d) == -1 && errno == ENFILE);
        CHECK(fcntl(c[0], F_SETPIPE_SZ, 16384) == -1 && errno == EPERM);
        CHECK(fcntl(c[0], F_SETPIPE_SZ, 4096) == 4096);
        int alias = dup(b[0]);
        CHECK(alias >= 0 && close(b[0]) == 0 && close(b[1]) == 0);
        CHECK(pipe(d) == -1 && errno == ENFILE);
        CHECK(close(alias) == 0 && pipe(d) == 0 && fcntl(d[0], F_GETPIPE_SZ) == 8192);
        _exit(0);
    }
    wait_success(child);
}

// Run only inside a test VM. These controls apply to the whole kernel.
static void pipe_limits(void) {
    DIR* directory_stream = opendir("/proc/sys/fs");
    CHECK(directory_stream);
    unsigned listed = 0;
    for (struct dirent* item; (item = readdir(directory_stream));)
        listed += !strcmp(item->d_name, "pipe-max-size") ||
                  !strcmp(item->d_name, "pipe-user-pages-hard") ||
                  !strcmp(item->d_name, "pipe-user-pages-soft");
    CHECK(listed == 3 && closedir(directory_stream) == 0);
    int max = open(pipe_max_size, O_RDWR);
    int hard = open(pipe_hard_pages, O_RDWR);
    int soft = open(pipe_soft_pages, O_RDWR);
    CHECK(max >= 0 && hard >= 0 && soft >= 0);
    char original_max[32], original_hard[32], original_soft[32];
    read_limit(max, original_max);
    read_limit(hard, original_hard);
    read_limit(soft, original_soft);
    write_limit(max, "4097", 4, "8192\n");
    write_limit(max, "2147483649", -1, "8192\n");
    write_limit(max, "0", 1, "4096\n");
    write_limit(max, "32768", 5, "32768\n");
    write_limit(hard, "18446744073709551615", 20, "18446744073709551615\n");
    write_limit(hard, "18446744073709551616", -1, "18446744073709551615\n");
    write_limit(soft, "-1", -1, original_soft);
    write_limit(soft, "0", 1, "0\n");
    write_limit(hard, "12", 2, "12\n");

    mode_t mask = umask(0);
    char directory[] = "/dev/shm/axiom-pipe-budget-XXXXXX";
    CHECK(mkdtemp(directory) && chmod(directory, 0755) == 0);
    char fifo[sizeof(directory) + sizeof("/fifo")];
    CHECK(snprintf(fifo, sizeof(fifo), "%s/fifo", directory) > 0 && mkfifo(fifo, 0666) == 0);
    umask(mask);
    hard_quota(max, fifo);
    CHECK(unlink(fifo) == 0 && rmdir(directory) == 0);
    write_limit(soft, "8", 1, "8\n");
    soft_quota();
    int privileged[2];
    CHECK(pipe(privileged) == 0 && fcntl(privileged[0], F_GETPIPE_SZ) == 65536);
    CHECK(close(privileged[0]) == 0 && close(privileged[1]) == 0);

    write_limit(soft, original_soft, strlen(original_soft), original_soft);
    write_limit(hard, original_hard, strlen(original_hard), original_hard);
    write_limit(max, original_max, strlen(original_max), original_max);
    CHECK(close(soft) == 0 && close(hard) == 0 && close(max) == 0);
    puts("NAMED_PIPE_LIMITS_PASS");
}

int main(int argc, char** argv) {
    CHECK(setvbuf(stdout, NULL, _IOLBF, 0) == 0);
    alarm(12);
    if (argc == 2 && !strcmp(argv[1], "--limits")) {
        pipe_limits();
        return 0;
    }
    if (argc == 2 &&
        (strcmp(argv[1], "--storage-create") == 0 || strcmp(argv[1], "--storage-reopen") == 0)) {
        storage_test(strcmp(argv[1], "--storage-create") == 0);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--ordinary"))
        CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
    else
        CHECK(argc == 1);
    char path[] = "/dev/shm/axiom-fifo-oracle-XXXXXX";
    CHECK(mkdtemp(path));
    int at = open(path, O_RDONLY | O_DIRECTORY);
    CHECK(at >= 0);
    umask(0027);
    CHECK(mkfifoat(at, "queue", 0666) == 0);
    CHECK(mkfifoat(at, "queue", 0666) == -1 && errno == EEXIST);
    CHECK(mkfifoat(at, "queue/", 0600) == -1 && errno == EEXIST);
    CHECK(mkfifoat(at, "missing/", 0600) == -1 && errno == ENOENT);
    struct stat found;
    CHECK(fstatat(at, "queue", &found, 0) == 0 && S_ISFIFO(found.st_mode));
    CHECK((found.st_mode & 0777) == 0640 && found.st_uid == geteuid() && found.st_size == 0);
    CHECK(syscall(SYS_mknod, "/dev/shm", S_IFIFO | 0600, 0) == -1 && errno == EEXIST);
    CHECK(syscall(SYS_mknodat, at, "raw", S_IFDIR | 0600, 0) == -1 && errno == EPERM);
    CHECK(symlinkat("absent", at, "symbol") == 0);
    CHECK(mkfifoat(at, "symbol", 0600) == -1 && errno == EEXIST);
    CHECK(unlinkat(at, "symbol", 0) == 0);
    CHECK(mkfifoat(at, "restricted", 0) == 0);
    if (geteuid() != 0)
        CHECK(openat(at, "restricted", O_RDONLY | O_NONBLOCK) == -1 && errno == EACCES);
    CHECK(unlinkat(at, "restricted", 0) == 0);
    puts("NAMED_PIPE_CASE create");
    readiness(at);
    capacity_and_readiness(-1);
    capacity_and_readiness(at);
    resize_wakes_writer();
    read_fault_after_head_slot();
    puts("NAMED_PIPE_CASE capacity-and-readiness");
    packet_pipes();
    packet_fifo(at);
    atomic_nonblocking_write();
    puts("NAMED_PIPE_CASE atomic-writev");
    retained_vector_write(-1);
    retained_vector_write(at);
    puts("NAMED_PIPE_CASE retained-writes");
    char fifo_path[sizeof(path) + sizeof("/queue")];
    int length = snprintf(fifo_path, sizeof(fifo_path), "%s/queue", path);
    CHECK(length > 0 && (size_t)length < sizeof(fifo_path));
    interrupted_partial_write(SIGUSR1, at, fifo_path);
    interrupted_partial_write(SIGPIPE, -1, NULL);
    puts("NAMED_PIPE_CASE partial-writes");
    rendezvous(at);
    peer_open_and_close(at, 0);
    peer_open_and_close(at, 1);
    puts("NAMED_PIPE_CASE transient-peer");
    interrupted_open(at, 0);
    interrupted_open(at, 1);
    cancellation(at);
    aliases(at);
    replace(at);
    CHECK(unlinkat(at, "queue", 0) == 0 && close(at) == 0 && rmdir(path) == 0);
    printf("NAMED_PIPE_PASS uid=%lu\n", (unsigned long)getuid());
    return 0;
}

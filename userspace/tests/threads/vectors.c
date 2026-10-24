// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef IO_LINKAGE
#define IO_LINKAGE "static"
#endif

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "THREAD_IO_VECTOR_FAIL line=%d: %s errno=%d\n", __LINE__, #expression, \
                    errno);                                                                        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static int empty_file(void) {
    char path[96];
    snprintf(path, sizeof(path), "/tmp/axiom64-vector-%ld", (long)getpid());
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0 && !unlink(path));
    return fd;
}

static void metadata(void) {
    unsigned char* bytes = mmap((void*)0x20000000, 4096, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(bytes == (void*)0x20000000);
    const size_t shapes[9][2] = {{16, 16},
                                 {INT64_MAX, 1},
                                 {INT64_MAX, INT64_MAX},
                                 {(size_t)INT64_MAX + 1, 0},
                                 {32, (size_t)INT64_MAX + 1},
                                 {32, INT64_MAX},
                                 {0x7ffff001, 0x7ffff001},
                                 {INT64_MAX, 0},
                                 {(size_t)INT64_MAX + 1, 0}};
    for (unsigned kind = 0; kind < 7; kind++) {
        for (unsigned number = 0; number < 11; number++) {
            int fd = -1, peer = -1;
            if (kind == 0 || kind == 4)
                fd = open("/dev/null", O_RDWR);
            else if (kind == 3)
                fd = empty_file();
            else {
                int pair[2];
                CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
                fd = pair[0];
                peer = pair[1];
                if (kind == 1 || kind == 2) {
                    unsigned char data[32];
                    for (unsigned n = 0; n < 32; n++)
                        data[n] = (unsigned char)(n * 7 + 3);
                    CHECK(write(peer, data, sizeof(data)) == sizeof(data));
                } else {
                    CHECK(!close(peer));
                    peer = -1;
                }
                CHECK(!fcntl(fd, F_SETFL, O_NONBLOCK));
            }
            CHECK(fd >= 0);
            memset(bytes, 0, 64);
            struct iovec vectors[2] = {{bytes, number < 9 ? shapes[number][0] : 0},
                                       {bytes + 16, number < 9 ? shapes[number][1] : 0}};
            size_t count = number == 9 ? 0 : number == 10 ? 1025 : number >= 7 ? 1 : 2;
            struct iovec* pointer = number >= 9 ? (void*)1 : vectors;
            struct msghdr message = {.msg_iov = pointer, .msg_iovlen = count, .msg_flags = 0x13579};
            errno = 0;
            long result = kind == 2 ? syscall(SYS_recvmsg, fd, &message, 0)
                          : kind == 6
                              ? syscall(SYS_sendmsg, fd, &message, 0)
                              : syscall(kind < 4 ? SYS_readv : SYS_writev, fd, pointer, count);
            int error = result < 0 ? errno : 0;
            int expected_error = number == 1 || number == 2 || number == 5   ? EFAULT
                                 : number == 3 || number == 4 || number == 8 ? EINVAL
                                 : number == 10 ? (kind == 2 || kind == 6 ? EMSGSIZE : EINVAL)
                                 : kind >= 5 && (number != 9 || kind == 6) ? EPIPE
                                                                           : 0;
            long expected = expected_error                              ? -1
                            : number == 9 || kind == 0 || kind == 3     ? 0
                            : kind == 4 && (number == 6 || number == 7) ? 0x7ffff000
                                                                        : 32;
            long remaining = -999;
            if (kind == 1 || kind == 2) {
                unsigned char after[64];
                remaining = recv(fd, after, sizeof(after), MSG_DONTWAIT);
                CHECK(remaining == (expected > 0 ? -1 : 32));
                if (remaining == -1)
                    CHECK(errno == EAGAIN);
                else {
                    for (unsigned n = 0; n < 32; n++)
                        CHECK(after[n] == (unsigned char)(n * 7 + 3));
                }
            }
            printf("THREAD_IO_VECTOR kind=%u case=%u result=%ld errno=%d flags=%x first=%u "
                   "remaining=%ld\n",
                   kind, number, result, error, kind == 2 || kind == 6 ? message.msg_flags : 0,
                   bytes[0], remaining);
            CHECK(result == expected && error == expected_error);
            CHECK(bytes[0] == ((kind == 1 || kind == 2) && expected > 0 ? 3 : 0));
            if (kind == 2 || kind == 6)
                CHECK(message.msg_flags == (kind == 2 && expected >= 0 ? 0 : 0x13579));
            CHECK(!close(fd));
            if (peer >= 0)
                CHECK(!close(peer));
        }
    }
    CHECK(!munmap(bytes, 4096));
}

static void read_faults(void) {
    unsigned char* memory =
        mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && !munmap(memory + 4096, 4096));
    for (unsigned kind = 0; kind < 6; kind++) {
        for (unsigned shape = 0; shape < 4; shape++) {
            int fd, peer = -1;
            unsigned char data[64];
            memset(data, 37, sizeof(data));
            if (kind < 2) {
                fd = empty_file();
                if (kind == 1)
                    CHECK(write(fd, data, 32) == 32);
                CHECK(lseek(fd, 0, SEEK_SET) == 0);
            } else {
                int pair[2];
                CHECK(!(kind < 4 ? pipe(pair) : socketpair(AF_UNIX, SOCK_STREAM, 0, pair)));
                fd = pair[0];
                peer = pair[1];
                CHECK(!fcntl(fd, F_SETFL, O_NONBLOCK));
                if (kind & 1)
                    CHECK(write(peer, data, 32) == 32);
            }
            unsigned char* base = shape < 2 ? memory + 4096 : memory + 4080;
            size_t length = shape == 0 ? 32 : shape == 1 ? 0 : shape == 2 ? 16 : 32;
            memset(memory, 0, 4096);
            struct iovec vector = {base, length};
            errno = 0;
            long result = syscall(SYS_readv, fd, &vector, 1);
            int error = result < 0 ? errno : 0;
            long offset = lseek(fd, 0, SEEK_CUR);
            long remaining = read(fd, data, sizeof(data));
            int expected_error = shape == 1 || kind == 0                   ? 0
                                 : !(kind & 1)                             ? EAGAIN
                                 : shape == 0 || (shape == 3 && kind != 1) ? EFAULT
                                                                           : 0;
            long expected = expected_error ? -1 : kind & 1 && shape >= 2 ? 16 : 0;
            printf("THREAD_IO_VECTOR_COPY kind=%u case=%u result=%ld errno=%d first=%u offset=%ld "
                   "remaining=%ld\n",
                   kind, shape, result, error, memory[4080], offset, remaining);
            CHECK(result == expected && error == expected_error);
            CHECK(memory[4080] == ((kind & 1) && shape >= 2 ? 37 : 0));
            CHECK(offset == (kind == 0 ? 0 : kind == 1 ? (expected > 0 ? 16 : 0) : -1));
            CHECK(remaining == (!(kind & 1) ? (kind == 0 ? 0 : -1) : expected > 0 ? 16 : 32));
            CHECK(!close(fd));
            if (peer >= 0)
                CHECK(!close(peer));
        }
    }
    CHECK(!munmap(memory, 4096));
}

static void write_faults(void) {
    unsigned char* memory =
        mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && !munmap(memory + 4096, 4096));
    memset(memory, 53, 4096);
    for (unsigned kind = 0; kind < 5; kind++) {
        for (unsigned shape = 0; shape < 4; shape++) {
            int fd, peer = -1;
            if (kind < 2)
                fd = open(kind == 0 ? "/dev/null" : "/dev/zero", O_RDWR);
            else if (kind == 2)
                fd = empty_file();
            else {
                int pair[2];
                CHECK(!(kind == 3 ? pipe(pair) : socketpair(AF_UNIX, SOCK_STREAM, 0, pair)));
                fd = pair[1];
                peer = pair[0];
                CHECK(!fcntl(peer, F_SETFL, O_NONBLOCK));
            }
            CHECK(fd >= 0);
            unsigned char* base = shape < 2 ? memory + 4096 : memory + 4080;
            size_t length = shape == 0 ? 32 : shape == 1 ? 0 : shape == 2 ? 16 : 32;
            struct iovec vector = {base, length};
            errno = 0;
            long result = syscall(SYS_writev, fd, &vector, 1);
            int error = result < 0 ? errno : 0;
            int expected_error = kind < 2 || shape == 1 || shape == 2 ? 0
                                 : shape == 0 || kind >= 3            ? EFAULT
                                                                      : 0;
            long expected = expected_error ? -1 : kind < 2 ? (long)length : shape >= 2 ? 16 : 0;
            unsigned char after[64];
            long received = -999;
            if (kind == 2) {
                CHECK(lseek(fd, 0, SEEK_SET) == 0);
                received = read(fd, after, sizeof(after));
            } else if (peer >= 0)
                received = read(peer, after, sizeof(after));
            printf("THREAD_IO_VECTOR_WRITE kind=%u case=%u result=%ld errno=%d received=%ld\n",
                   kind, shape, result, error, received);
            CHECK(result == expected && error == expected_error);
            if (kind >= 2) {
                CHECK(received == (expected > 0 ? expected : kind == 2 ? 0 : -1));
                for (long n = 0; n < received; n++)
                    CHECK(after[n] == 53);
            }
            CHECK(!close(fd));
            if (peer >= 0)
                CHECK(!close(peer));
        }
    }
    CHECK(!munmap(memory, 4096));
}

static volatile sig_atomic_t broken_pipe;

static void broken_pipe_signal(int signal_number) {
    if (signal_number == SIGPIPE)
        broken_pipe++;
}

static void empty_sends(void) {
    struct sigaction previous, action = {.sa_handler = broken_pipe_signal};
    CHECK(!sigemptyset(&action.sa_mask) && !sigaction(SIGPIPE, &action, &previous));
    for (unsigned operation = 0; operation < 2; operation++) {
        for (unsigned state = 0; state < 4; state++) {
            for (unsigned quiet = 0; quiet < 2; quiet++) {
                int pair[2];
                CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, pair));
                if (state == 1)
                    CHECK(!close(pair[1]));
                else if (state == 2)
                    CHECK(!shutdown(pair[0], SHUT_WR));
                else if (state == 3)
                    CHECK(!shutdown(pair[1], SHUT_RD));
                struct msghdr message = {.msg_iov = (void*)1, .msg_iovlen = 0};
                broken_pipe = 0;
                errno = 0;
                int flags = quiet ? MSG_NOSIGNAL : 0;
                long result = operation ? syscall(SYS_sendmsg, pair[0], &message, flags)
                                        : syscall(SYS_sendto, pair[0], (void*)1, 0, flags, 0, 0);
                int error = result < 0 ? errno : 0;
                printf("THREAD_IO_VECTOR_EMPTY operation=%u state=%u quiet=%u result=%ld errno=%d "
                       "signals=%d\n",
                       operation, state, quiet, result, error, (int)broken_pipe);
                CHECK(result == (state ? -1 : 0) && error == (state ? EPIPE : 0));
                CHECK(broken_pipe == (state && !quiet ? 1 : 0));
                broken_pipe = 0;
                CHECK(syscall(SYS_writev, pair[0], (void*)1, 0) == 0 && !broken_pipe);
                CHECK(!close(pair[0]));
                if (state != 1)
                    CHECK(!close(pair[1]));
            }
        }
    }
    CHECK(!sigaction(SIGPIPE, &previous, 0));
}

static void vector_chunks(void) {
    unsigned char* memory =
        mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && !munmap(memory + 4096, 4096));
    for (unsigned operation = 0; operation < 6; operation++) {
        int writing = operation & 1;
        for (unsigned layout = 0; layout < 2; layout++) {
            for (unsigned short_input = 0; short_input < (writing ? 1u : 2u); short_input++) {
                int pair[2];
                CHECK(!(operation < 2 ? pipe(pair) : socketpair(AF_UNIX, SOCK_STREAM, 0, pair)));
                CHECK(!fcntl(pair[0], F_SETFL, O_NONBLOCK));
                unsigned char data[64];
                memset(data, 71, sizeof(data));
                if (!writing)
                    CHECK(write(pair[1], data, short_input ? 8 : 32) == (short_input ? 8 : 32));
                memset(memory, writing ? 71 : 0, 16);
                struct iovec vectors[3] = {{memory + 4096, 0}, {memory, 16}, {memory + 4096, 16}};
                struct iovec* first = vectors + (layout ? 0 : 1);
                size_t count = layout ? 3 : 2;
                struct msghdr message = {
                    .msg_iov = first, .msg_iovlen = count, .msg_flags = 0x13579};
                int fd = writing ? pair[1] : pair[0];
                errno = 0;
                long result = operation == 4 ? syscall(SYS_recvmsg, fd, &message, 0)
                              : operation == 5
                                  ? syscall(SYS_sendmsg, fd, &message, 0)
                                  : syscall(writing ? SYS_writev : SYS_readv, fd, first, count);
                int error = result < 0 ? errno : 0;
                long queued = read(pair[0], data, sizeof(data));
                int queue_error = queued < 0 ? errno : 0;
                printf("THREAD_IO_VECTOR_CHUNK operation=%u layout=%u short=%u result=%ld errno=%d "
                       "first=%u queued=%ld flags=%x\n",
                       operation, layout, short_input, result, error, memory[0], queued,
                       operation >= 4 ? message.msg_flags : 0);
                CHECK(result == (short_input ? 8 : -1) && error == (short_input ? 0 : EFAULT));
                CHECK(memory[0] == 71);
                CHECK(queued == (writing || short_input ? -1 : 32));
                if (queued < 0)
                    CHECK(queue_error == EAGAIN);
                for (long n = 0; n < queued; n++)
                    CHECK(data[n] == 71);
                if (operation >= 4)
                    CHECK(message.msg_flags == (operation == 4 && short_input ? 0 : 0x13579));
                CHECK(!close(pair[0]) && !close(pair[1]));
            }
        }
    }
    CHECK(!munmap(memory, 4096));
}

void io_vectors_test(void) {
    metadata();
    read_faults();
    write_faults();
    empty_sends();
    vector_chunks();
    printf("THREAD_IO_VECTORS_PASS linkage=%s metadata=77 faults=24 writes=20 empty=16 chunks=18\n",
           IO_LINKAGE);
}

#ifdef IO_VECTORS_MAIN
int main(void) {
    CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    io_vectors_test();
    return 0;
}
#endif

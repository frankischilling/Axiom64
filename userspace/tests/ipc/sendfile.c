// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/sendfile.c
 * @brief   File descriptor transfers through sendfile.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks transfer offsets, pipe and socket backpressure, descriptor lifetime,
 * and file size limits for sendfile.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "SENDFILE_FAIL line=%d errno=%d %s\n", __LINE__, errno, #condition);   \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned char payload[512 * 1024], received[sizeof(payload)];

static void close_pair(const int pair[2]) {
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
}

static int create_file(const void* data, size_t length) {
    char path[] = "/tmp/axiom-sendfile-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0 && unlink(path) == 0);
    if (length)
        CHECK(write(fd, data, length) == (ssize_t)length && lseek(fd, 0, SEEK_SET) == 0);
    return fd;
}

static void read_exact(int fd, void* data, size_t length) {
    for (size_t used = 0; used < length;) {
        ssize_t count = read(fd, (char*)data + used, length - used);
        CHECK(count > 0);
        used += (size_t)count;
    }
}

static size_t drain(int fd) {
    size_t used = 0;
    while (used < sizeof(received)) {
        ssize_t count = recv(fd, received + used, sizeof(received) - used, MSG_DONTWAIT);
        if (count == -1 && errno == EAGAIN)
            break;
        CHECK(count > 0);
        used += (size_t)count;
    }
    return used;
}

static void arguments(int input, int output) {
    int pipefd[2], sockets[2];
    CHECK(pipe(pipefd) == 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    off_t offset = 0;
    CHECK(sendfile(-1, input, NULL, 1) == -1 && errno == EBADF);
    CHECK(sendfile(output, -1, NULL, 1) == -1 && errno == EBADF);
    CHECK(sendfile(output, -1, (off_t*)(uintptr_t)1, 1) == -1 && errno == EFAULT);
    CHECK(sendfile(output, pipefd[0], &offset, 1) == -1 && errno == ESPIPE && offset == 0);
    CHECK(sendfile(output, sockets[0], &offset, 1) == -1 && errno == ESPIPE && offset == 0);
    CHECK(sendfile(output, pipefd[0], NULL, 1) == -1 && errno == EINVAL);
    CHECK(sendfile(output, sockets[0], NULL, 1) == -1 && errno == EINVAL);
    CHECK(sendfile(pipefd[1], pipefd[0], NULL, 1) == -1 && errno == EINVAL);
    offset = -1;
    CHECK(sendfile(output, input, &offset, 1) == -1 && errno == EINVAL && offset == -1);
    offset = INT64_MAX;
    CHECK(sendfile(output, input, &offset, 1) == -1 && errno == EINVAL && offset == INT64_MAX);
    CHECK(sendfile(output, input, NULL, SIZE_MAX) == -1 && errno == EINVAL);
    CHECK(sendfile(output, pipefd[1], NULL, 0) == -1 && errno == EBADF);
    CHECK(sendfile(pipefd[0], input, NULL, 0) == -1 && errno == EBADF);
    int flags = fcntl(output, F_GETFL);
    CHECK(flags >= 0 && fcntl(output, F_SETFL, flags | O_APPEND) == 0);
    CHECK(sendfile(output, input, NULL, 1) == -1 && errno == EINVAL);
    CHECK(fcntl(output, F_SETFL, flags) == 0);
    CHECK(sendfile(output, input, NULL, 0) == 0 && lseek(input, 0, SEEK_CUR) == 0);
    close_pair(pipefd);
    close_pair(sockets);
    puts("SENDFILE_CASE arguments");
}

static void file_offsets(int input, int output) {
    const off_t start = 4093;
    const size_t length = 9001;
    off_t offset = start;
    CHECK(lseek(input, 31, SEEK_SET) == 31 && lseek(output, 19, SEEK_SET) == 19);
    CHECK(sendfile(output, input, &offset, length) == (ssize_t)length);
    CHECK(offset == start + (off_t)length && lseek(input, 0, SEEK_CUR) == 31);
    CHECK(lseek(output, 0, SEEK_CUR) == 19 + (off_t)length);
    CHECK(pread(output, received, length, 19) == (ssize_t)length);
    CHECK(!memcmp(payload + start, received, length));
    CHECK(lseek(input, sizeof(payload) - 7, SEEK_SET) == (off_t)sizeof(payload) - 7);
    CHECK(sendfile(output, input, NULL, 12) == 7);
    CHECK(sendfile(output, input, NULL, 12) == 0);
    CHECK(lseek(input, 0, SEEK_CUR) == (off_t)sizeof(payload));
    CHECK(lseek(output, 0, SEEK_CUR) == 19 + (off_t)length + 7);
    CHECK(pread(output, received, 7, 19 + (off_t)length) == 7);
    CHECK(!memcmp(payload + sizeof(payload) - 7, received, 7));

    CHECK(lseek(input, 21, SEEK_SET) == 21);
    offset = 3;
    CHECK(sendfile(input, input, &offset, 12) == 12 && offset == 15);
    CHECK(lseek(input, 0, SEEK_CUR) == 33);
    CHECK(pread(input, received, 12, 21) == 12 && !memcmp(payload + 3, received, 12));
    CHECK(pwrite(input, payload + 21, 12, 21) == 12);
    puts("SENDFILE_CASE file-offsets");
}

static void copyout_fault(int input, int output) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    off_t* offset = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(offset != MAP_FAILED);
    *offset = 11;
    CHECK(mprotect(offset, page, PROT_READ) == 0);
    CHECK(sendfile(output, -1, offset, 1) == -1 && errno == EFAULT);
    CHECK(lseek(input, 0, SEEK_SET) == 0 && lseek(output, 0, SEEK_SET) == 0);
    CHECK(sendfile(output, input, offset, 17) == -1 && errno == EFAULT);
    CHECK(*offset == 11 && lseek(input, 0, SEEK_CUR) == 0);
    CHECK(lseek(output, 0, SEEK_CUR) == 17);
    CHECK(pread(output, received, 17, 0) == 17 && !memcmp(payload + 11, received, 17));
    CHECK(munmap(offset, page) == 0);
    puts("SENDFILE_CASE copyout-fault");
}

static void file_size_limit(int input) {
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_FSIZE, &original) == 0);
    limit = original;
    limit.rlim_cur = 11;
    int output = create_file(NULL, 0);
    off_t offset = 19;
    void (*previous)(int) = signal(SIGXFSZ, SIG_IGN);
    CHECK(previous != SIG_ERR && setrlimit(RLIMIT_FSIZE, &limit) == 0);
    CHECK(sendfile(output, input, &offset, 22) == 11 && offset == 30);
    CHECK(sendfile(output, input, &offset, 1) == -1 && errno == EFBIG && offset == 30);
    CHECK(setrlimit(RLIMIT_FSIZE, &original) == 0 && signal(SIGXFSZ, previous) != SIG_ERR);
    CHECK(lseek(output, 0, SEEK_CUR) == 11 && lseek(input, 0, SEEK_CUR) == 0);
    CHECK(pread(output, received, 11, 0) == 11 && !memcmp(payload + 19, received, 11));
    CHECK(close(output) == 0);
    puts("SENDFILE_CASE file-size-limit");
}

static void pipe_output(int input) {
    int pipefd[2];
    CHECK(pipe2(pipefd, O_NONBLOCK) == 0);
    CHECK(fcntl(pipefd[1], F_SETPIPE_SZ, 4096) == 4096);
    struct pollfd read_end = {.fd = pipefd[0], .events = POLLIN};
    CHECK(poll(&read_end, 1, 0) == 0 && lseek(input, 5, SEEK_SET) == 5);
    CHECK(sendfile(pipefd[1], input, NULL, 8192) == 4091);
    CHECK(poll(&read_end, 1, 0) == 1 && (read_end.revents & POLLIN));
    CHECK(sendfile(pipefd[1], input, NULL, 8192) == -1 && errno == EAGAIN);
    CHECK(lseek(input, 0, SEEK_CUR) == 4096);
    read_exact(pipefd[0], received, 4091);
    CHECK(!memcmp(payload + 5, received, 4091) && poll(&read_end, 1, 0) == 0);
    off_t offset = 7;
    CHECK(sendfile(pipefd[1], input, &offset, 13) == 13 && offset == 20);
    CHECK(lseek(input, 0, SEEK_CUR) == 4096);
    read_exact(pipefd[0], received, 13);
    CHECK(!memcmp(payload + 7, received, 13));
    CHECK(close(pipefd[0]) == 0);
    CHECK(sendfile(pipefd[1], input, &offset, 13) == -1 && errno == EPIPE && offset == 20);
    CHECK(close(pipefd[1]) == 0);
    puts("SENDFILE_CASE pipe-output");
}

static void memory_devices(int input, int legacy) {
    int null = open("/dev/null", O_WRONLY);
    int zero = open("/dev/zero", O_RDONLY);
    int pipefd[2];
    CHECK(null >= 0 && zero >= 0 && pipe(pipefd) == 0);
    off_t offset = 5;
    CHECK(sendfile(null, input, &offset, 17) == 17 && offset == 22);
    CHECK(lseek(input, 0, SEEK_CUR) == 4096);
    offset = 0;
    if (legacy) {
        CHECK(sendfile(pipefd[1], zero, &offset, 31) == -1 && errno == EINVAL && offset == 0);
    } else {
        CHECK(sendfile(pipefd[1], zero, &offset, 31) == 31 && offset == 0);
        read_exact(pipefd[0], received, 31);
        CHECK(!memcmp(received, (char[31]){0}, 31));
        CHECK(sendfile(null, zero, NULL, 509) == 509 && lseek(zero, 0, SEEK_CUR) == 0);
    }
    close_pair(pipefd);
    CHECK(close(zero) == 0 && close(null) == 0);
    puts("SENDFILE_CASE memory-devices");
}

static void unix_sockets(int input) {
    int sockets[2], pipefd[2];
    for (int type = SOCK_STREAM; type <= SOCK_DGRAM; ++type) {
        CHECK(socketpair(AF_UNIX, type, 0, sockets) == 0);
        off_t offset = sizeof(payload) - 9001;
        CHECK(sendfile(sockets[0], input, &offset, 10001) == 9001);
        CHECK(offset == (off_t)sizeof(payload) && lseek(input, 0, SEEK_CUR) == 4096);
        size_t count = drain(sockets[1]);
        CHECK(count == 9001 && !memcmp(payload + offset - 9001, received, count));
        close_pair(sockets);
    }

    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets) == 0 && pipe(pipefd) == 0);
    CHECK(write(sockets[0], "socket", 6) == 6);
    CHECK(sendfile(pipefd[1], sockets[1], NULL, 6) == 6);
    read_exact(pipefd[0], received, 6);
    CHECK(!memcmp(received, "socket", 6));
    CHECK(sendfile(pipefd[1], sockets[1], NULL, 6) == -1 && errno == EAGAIN);
    CHECK(shutdown(sockets[0], SHUT_WR) == 0);
    CHECK(sendfile(pipefd[1], sockets[1], NULL, 6) == 0);
    close_pair(pipefd);
    close_pair(sockets);
    puts("SENDFILE_CASE unix-sockets");
}

static int bind_loopback(int family, int type, struct sockaddr_storage* address, socklen_t* size) {
    struct sockaddr_in ipv4 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    *size = family == AF_INET6 ? sizeof(ipv6) : sizeof(ipv4);
    memcpy(address, family == AF_INET6 ? (void*)&ipv6 : (void*)&ipv4, *size);
    int receiver = socket(family, type, 0);
    CHECK(receiver >= 0 && bind(receiver, (struct sockaddr*)address, *size) == 0);
    CHECK(getsockname(receiver, (struct sockaddr*)address, size) == 0);
    return receiver;
}

static void tcp_sockets(int input) {
    int families[] = {AF_INET, AF_INET6};
    for (size_t i = 0; i < sizeof(families) / sizeof(families[0]); ++i) {
        int af = families[i];
        struct sockaddr_storage address;
        socklen_t length;
        int listener = bind_loopback(af, SOCK_STREAM, &address, &length);
        CHECK(listen(listener, 1) == 0);
        int sender = socket(af, SOCK_STREAM, 0);
        CHECK(sender >= 0 && connect(sender, (struct sockaddr*)&address, length) == 0);
        int receiver = accept(listener, NULL, NULL);
        CHECK(receiver >= 0 && close(listener) == 0);

        const off_t start = sizeof(payload) - 9001;
        off_t offset = start;
        CHECK(sendfile(sender, input, &offset, 12000) == 9001 && offset == (off_t)sizeof(payload));
        struct pollfd ready = {.fd = receiver, .events = POLLIN};
        CHECK(poll(&ready, 1, 3000) == 1);
        read_exact(receiver, received, 9001);
        CHECK(!memcmp(payload + start, received, 9001));

        int pipefd[2];
        CHECK(pipe(pipefd) == 0 && write(sender, "tcp", 3) == 3);
        CHECK(poll(&ready, 1, 3000) == 1 && sendfile(pipefd[1], receiver, NULL, 3) == 3);
        read_exact(pipefd[0], received, 3);
        CHECK(!memcmp(received, "tcp", 3));
        close_pair(pipefd);
        CHECK(close(sender) == 0 && close(receiver) == 0);
    }
    puts("SENDFILE_CASE tcp-sockets");
}

static void udp_sockets(int input, int legacy) {
    for (unsigned family = 0; family < 2; ++family) {
        int af = family ? AF_INET6 : AF_INET;
        struct sockaddr_storage address;
        socklen_t length;
        int receiver = bind_loopback(af, SOCK_DGRAM, &address, &length);
        int sender = socket(af, SOCK_DGRAM, 0);
        CHECK(sender >= 0 && connect(sender, (struct sockaddr*)&address, length) == 0);
        const off_t start = sizeof(payload) - 9001;
        off_t offset = start;
        CHECK(sendfile(sender, input, &offset, 9001) == 9001 && offset == (off_t)sizeof(payload));
        struct pollfd ready = {.fd = receiver, .events = POLLIN};
        CHECK(poll(&ready, 1, 3000) == 1);
        if (legacy)
            CHECK(drain(receiver) == 9001);
        else
            CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) == 9001);
        CHECK(!memcmp(payload + start, received, 9001));
        CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) == -1 && errno == EAGAIN);

        if (!legacy) {
            offset = sizeof(payload) - 51;
            CHECK(sendfile(sender, input, &offset, 91) == 51 && offset == (off_t)sizeof(payload));
            // Linux IPv6 UDP keeps an EOF-short send pending until the next send.
            if (family) {
                CHECK(poll(&ready, 1, 0) == 0);
                CHECK(send(sender, "!", 1, 0) == 1);
            }
            CHECK(poll(&ready, 1, 3000) == 1);
            CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) == 51 + family);
            CHECK(!memcmp(payload + sizeof(payload) - 51, received, 51));
            if (family)
                CHECK(received[51] == '!');
            CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) == -1 &&
                  errno == EAGAIN);
        }

        CHECK(send(sender, "pre", 3, MSG_MORE) == 3);
        CHECK(sendfile(sender, input, &offset, 3) == 0);
        CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) == -1 && errno == EAGAIN);
        CHECK(send(sender, "post", 4, 0) == 4 && poll(&ready, 1, 3000) == 1);
        CHECK(recv(receiver, received, sizeof(received), MSG_DONTWAIT) == 7);
        CHECK(!memcmp(received, "prepost", 7));
        const int ends[] = {sender, receiver};
        close_pair(ends);
    }
    puts("SENDFILE_CASE udp-sockets");
}

struct transfer {
    int output, input, ready, done;
    off_t offset;
    off_t* external_offset;
    ssize_t count;
    int error;
};

static void* transfer(void* argument) {
    struct transfer* job = argument;
    CHECK(write(job->ready, "r", 1) == 1);
    off_t* offset = job->external_offset ? job->external_offset : &job->offset;
    job->count = sendfile(job->output, job->input, offset, sizeof(payload));
    job->error = errno;
    CHECK(write(job->done, "d", 1) == 1);
    return NULL;
}

static void start_transfer(struct transfer* job, pthread_t* thread, int ready[2], int done[2]) {
    CHECK(pipe(ready) == 0 && pipe(done) == 0);
    job->ready = ready[1];
    job->done = done[1];
    CHECK(pthread_create(thread, NULL, transfer, job) == 0);
    char byte;
    read_exact(ready[0], &byte, 1);
    CHECK(byte == 'r');
    struct pollfd completed = {.fd = done[0], .events = POLLIN};
    CHECK(poll(&completed, 1, 70) == 0);
}

static void join_transfer(pthread_t thread, const int ready[2], const int done[2]) {
    struct pollfd completed = {.fd = done[0], .events = POLLIN};
    CHECK(poll(&completed, 1, 4000) == 1 && pthread_join(thread, NULL) == 0);
    close_pair(ready);
    close_pair(done);
}

static void retain_descriptions(void) {
    int pipefd[2], ready[2], done[2];
    CHECK(pipe(pipefd) == 0 && fcntl(pipefd[1], F_SETPIPE_SZ, 4096) == 4096);
    CHECK(write(pipefd[1], "x", 1) == 1);
    int source = create_file("held source", 11);
    int replacement = create_file("new descriptor", 14);
    struct transfer job = {.output = pipefd[1], .input = source, .offset = 5};
    pthread_t thread;
    start_transfer(&job, &thread, ready, done);
    CHECK(dup2(replacement, source) == source && dup2(replacement, pipefd[1]) == pipefd[1]);
    char byte;
    read_exact(pipefd[0], &byte, 1);
    CHECK(byte == 'x');
    join_transfer(thread, ready, done);
    CHECK(job.count == 6 && job.offset == 11 && lseek(replacement, 0, SEEK_CUR) == 0);
    read_exact(pipefd[0], received, 6);
    CHECK(!memcmp(received, "source", 6));
    CHECK(close(source) == 0 && close(replacement) == 0);
    close_pair(pipefd);
    puts("SENDFILE_CASE retained-descriptions");
}

static void caught(int signal_number) {
    (void)signal_number;
}

static void socket_backpressure(int input) {
    int sockets[2], ready[2], done[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    int size = 8192;
    CHECK(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
    CHECK(fcntl(sockets[0], F_SETFL, O_NONBLOCK) == 0);
    off_t offset = 9;
    ssize_t count = sendfile(sockets[0], input, &offset, sizeof(payload));
    CHECK(count > 0 && count < (ssize_t)sizeof(payload) - 9 && offset == 9 + count);
    CHECK(sendfile(sockets[0], input, &offset, 1) == -1 && errno == EAGAIN && offset == 9 + count);
    CHECK(drain(sockets[1]) == (size_t)count && !memcmp(received, payload + 9, count));
    CHECK(fcntl(sockets[0], F_SETFL, 0) == 0);

    struct sigaction action = {.sa_handler = caught, .sa_flags = SA_RESTART}, previous;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, &previous) == 0);
    struct transfer job = {.output = sockets[0], .input = input, .offset = offset};
    pthread_t thread;
    start_transfer(&job, &thread, ready, done);
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    join_transfer(thread, ready, done);
    CHECK(job.count > 0 && job.count < (ssize_t)sizeof(payload) - offset);
    CHECK(job.offset == offset + job.count);
    CHECK(drain(sockets[1]) == (size_t)job.count && !memcmp(received, payload + offset, job.count));
    CHECK(lseek(input, 0, SEEK_CUR) == 4096);
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0);
    close_pair(sockets);
    puts("SENDFILE_CASE socket-backpressure");
}

static void interrupted_copyout(int input) {
    int pipefd[2], ready[2], done[2];
    CHECK(pipe(pipefd) == 0 && fcntl(pipefd[1], F_SETPIPE_SZ, 4096) == 4096);
    CHECK(write(pipefd[1], "x", 1) == 1);
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    off_t* offset = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(offset != MAP_FAILED);
    *offset = 8;
    CHECK(mprotect(offset, page, PROT_READ) == 0);
    struct sigaction action = {.sa_handler = caught, .sa_flags = SA_RESTART}, previous;
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, &previous) == 0);
    pthread_t thread;
    struct transfer job = {.output = pipefd[1], .input = input, .external_offset = offset};
    start_transfer(&job, &thread, ready, done);
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    join_transfer(thread, ready, done);
    CHECK(job.count == -1 && job.error == EFAULT && *offset == 8);
    CHECK(sigaction(SIGUSR1, &previous, NULL) == 0 && munmap(offset, page) == 0);
    char byte;
    read_exact(pipefd[0], &byte, 1);
    CHECK(byte == 'x');
    close_pair(pipefd);
    puts("SENDFILE_CASE interrupted-copyout");
}

int main(int argc, char** argv) {
    int legacy = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--ordinary")) {
            CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        } else {
            CHECK(!strcmp(argv[i], "--legacy-sendfile"));
            legacy = 1;
        }
    }
    CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    for (size_t i = 0; i < sizeof(payload); ++i)
        payload[i] = (unsigned char)((i ^ (i / 31)) % 251);
    int input = create_file(payload, sizeof(payload)), output = create_file(NULL, 0);
    arguments(input, output);
    file_offsets(input, output);
    copyout_fault(input, output);
    file_size_limit(input);
    pipe_output(input);
    memory_devices(input, legacy);
    unix_sockets(input);
    tcp_sockets(input);
    udp_sockets(input, legacy);
    retain_descriptions();
    socket_backpressure(input);
    interrupted_copyout(input);
    CHECK(close(input) == 0 && close(output) == 0);
    printf("SENDFILE_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}

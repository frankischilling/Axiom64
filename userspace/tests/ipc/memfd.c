// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/ipc/memfd.c
 * @brief   Linux anonymous file and seal regression tests.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks descriptor ownership, sparse data, file-backed page faults, and seal enforcement.
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
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 16
#endif
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 32
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL 8
#define MFD_EXEC 16
#endif

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "MEMFD_FAIL line=%d errno=%d %s\n", __LINE__, errno, #expr);           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static size_t page;

static int memory_file(void) {
    int fd = memfd_create("surface", MFD_ALLOW_SEALING);
    CHECK(fd >= 0 && fcntl(fd, F_GET_SEALS) == 0);
    return fd;
}

static void check_bus(int signal_number, siginfo_t* info, void* context) {
    (void)context;
    _exit(signal_number == SIGBUS && info->si_code == BUS_ADRERR ? 79 : 71);
}

static void expect_fault(volatile char* address, int expected) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (expected == SIGBUS) {
            struct sigaction action = {.sa_sigaction = check_bus, .sa_flags = SA_SIGINFO};
            CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGBUS, &action, NULL) == 0);
        }
        volatile char value = *address;
        (void)value;
        _exit(72);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    if (expected == SIGBUS)
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 79);
    else
        CHECK(WIFSIGNALED(status) && WTERMSIG(status) == expected);
}

static void arguments(void) {
    CHECK(syscall(SYS_memfd_create, (void*)(uintptr_t)1, 0) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_memfd_create, (void*)(uintptr_t)1, 0x4000) == -1 && errno == EINVAL);
    CHECK(memfd_create("", MFD_EXEC | MFD_NOEXEC_SEAL) == -1 && errno == EINVAL);
    char name[251];
    memset(name, 'n', 250);
    name[250] = 0;
    CHECK(memfd_create(name, 0) == -1 && errno == EINVAL);
    name[249] = 0;
    mode_t mask = umask(077);
    int fd = memfd_create(name, MFD_CLOEXEC);
    umask(mask);
    CHECK(fd >= 0 && fcntl(fd, F_GETFD) == FD_CLOEXEC);
    CHECK((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR);
    struct stat meta;
    struct statfs fs;
    CHECK(fstat(fd, &meta) == 0 && S_ISREG(meta.st_mode) && (meta.st_mode & 0777) == 0777);
    CHECK(meta.st_nlink == 0 && meta.st_size == 0 && meta.st_uid == getuid());
    CHECK(fstatfs(fd, &fs) == 0 && fs.f_type == 0x01021994);
    CHECK(fcntl(fd, F_GET_SEALS) == F_SEAL_SEAL);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == -1 && errno == EPERM);
    int alias = dup(fd);
    CHECK(alias >= 0 && fcntl(alias, F_GETFD) == 0 && fcntl(alias, F_GET_SEALS) == F_SEAL_SEAL);
    CHECK(close(alias) == 0 && close(fd) == 0);
    puts("MEMFD_CASE arguments");
}

static void descriptor_exec(const char* program) {
    int keep = memory_file(), drop = memfd_create("drop", MFD_CLOEXEC);
    CHECK(keep >= 0 && drop >= 0 && pwrite(keep, "e", 1, 0) == 1);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char first[16], second[16];
        CHECK(snprintf(first, sizeof(first), "%d", keep) > 0);
        CHECK(snprintf(second, sizeof(second), "%d", drop) > 0);
        execl(program, program, "--exec-child", first, second, (char*)NULL);
        CHECK(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(keep) == 0 && close(drop) == 0);
    puts("MEMFD_CASE exec-descriptors");
}

static void sparse_pages(void) {
    int fd = memory_file();
    off_t large = ((off_t)1 << 33) + (off_t)page;
    CHECK(ftruncate(fd, large) == 0);
    struct stat meta;
    CHECK(fstat(fd, &meta) == 0 && meta.st_blocks == 0 && meta.st_size == large);
    CHECK(pwrite(fd, "first", 5, 7) == 5);
    CHECK(pwrite(fd, "last", 4, large - 4) == 4);
    CHECK(fstat(fd, &meta) == 0 && meta.st_blocks == (blkcnt_t)(2 * page / 512));
    char bytes[8];
    CHECK(pread(fd, bytes, 8, large / 2) == 8 && !memcmp(bytes, (char[8]){0}, 8));
    CHECK(lseek(fd, 7, SEEK_SET) == 7);
    CHECK(read(fd, bytes, 5) == 5 && !memcmp(bytes, "first", 5));
    char* last = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, large - page);
    CHECK(last != MAP_FAILED && !memcmp(last + page - 4, "last", 4));
    last[page - 3] = 'o';
    CHECK(pread(fd, bytes, 4, large - 4) == 4 && !memcmp(bytes, "lost", 4));
    CHECK(lseek(fd, 0, SEEK_CUR) == 12);
    CHECK(munmap(last, page) == 0 && ftruncate(fd, 3) == 0);
    CHECK(fstat(fd, &meta) == 0 && meta.st_blocks <= (blkcnt_t)(page / 512) && meta.st_size == 3);
    CHECK(close(fd) == 0);
    puts("MEMFD_CASE sparse-pages");
}

static int receive_fd_after_close(int fd) {
    int sockets[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    char data = 's';
    struct iovec io = {.iov_base = &data, .iov_len = 1};

    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr message = {
        .msg_iov = &io,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes),
    };
    struct cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    CHECK(sendmsg(sockets[0], &message, 0) == 1 && close(fd) == 0);
    data = 0;
    memset(control.bytes, 0, sizeof(control.bytes));
    CHECK(recvmsg(sockets[1], &message, MSG_CMSG_CLOEXEC) == 1 && data == 's');
    header = CMSG_FIRSTHDR(&message);
    CHECK(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS);
    CHECK(header->cmsg_len == CMSG_LEN(sizeof(int)));
    memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC);
    CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
    return fd;
}

static void mappings(void) {
    int fd = memory_file();
    CHECK(ftruncate(fd, 2 * page) == 0 && pwrite(fd, "a", 1, 0) == 1);
    fd = receive_fd_after_close(fd);
    char* shared = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char* private = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(shared != MAP_FAILED && private != MAP_FAILED);
    CHECK(mmap(shared + page, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
               -1, 0) == MAP_FAILED &&
          errno == EEXIST);
    CHECK(private[0] == 'a');
    CHECK(pwrite(fd, "b", 1, 0) == 1 && private[0] == 'b' && shared[0] == 'b');
    private[0] = 'c';
    CHECK(shared[0] == 'b');
    CHECK(close(fd) == 0);

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(private[0] == 'c' && shared[0] == 'b');
        private[0] = 'd';
        private[page] = 'p';
        shared[page] = 's';
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(private[0] == 'c' && shared[0] == 'b' && private[page] == 's' && shared[page] == 's');
    CHECK(munmap(shared, page * 2) == 0 && munmap(private, page * 2) == 0);
    puts("MEMFD_CASE descriptor-and-mapping-lifetime");
}

static void mapping_faults(void) {
    int fd = memory_file();
    CHECK(ftruncate(fd, 2 * page) == 0);
    char* map = mmap(NULL, 4 * page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char* private = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(map != MAP_FAILED && private != MAP_FAILED);
    CHECK(mprotect(map + 2 * page, page, PROT_READ) == 0);
    expect_fault(map + 2 * page, SIGBUS);
    CHECK(mprotect(map + 2 * page, page, PROT_READ | PROT_WRITE) == 0);
    private[page] = 'p';
    map[page] = 'm';
    CHECK(ftruncate(fd, page) == 0);
    expect_fault(map + page, SIGBUS);
    expect_fault(private + page, SIGBUS);
    CHECK(ftruncate(fd, 4 * page) == 0 && map[page] == 0 && private[page] == 0);
    map[page * 2] = 'c';
    map[page * 3] = 'd';
    CHECK(mprotect(map + page * 2, page, PROT_NONE) == 0);
    expect_fault(map + page * 2, SIGSEGV);
    CHECK(mprotect(map + page * 2, page, PROT_READ) == 0 && map[page * 2] == 'c');
    CHECK(mmap(map + page, page, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0) == map + page);
    map[page] = 'x';
    CHECK(munmap(map + page * 2, page) == 0);
    CHECK(ftruncate(fd, page) == 0);
    CHECK(map[page] == 'x');
    expect_fault(map + page * 3, SIGBUS);
    CHECK(ftruncate(fd, 4 * page) == 0);
    CHECK(map[page * 3] == 0 && map[page] == 'x');
    CHECK(munmap(map, 4 * page) == 0 && munmap(private, 2 * page) == 0 && close(fd) == 0);
    puts("MEMFD_CASE mapping-faults-and-replacement");
}

static void io_faulting_ranges(void) {
    int first = memory_file(), second = memory_file();
    CHECK(ftruncate(first, 2 * page) == 0 && ftruncate(second, page) == 0);
    char* area = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE, MAP_SHARED, first, 0);
    char* private = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, first, 0);
    CHECK(area != MAP_FAILED && private != MAP_FAILED);
    CHECK(pwrite(first, "a", 1, 0) == 1 && pwrite(second, "b", 1, 0) == 1);
    CHECK(pread(second, private, 1, 0) == 1 && private[0] == 'b' && area[0] == 'a');
    CHECK(pread(second, area + page, 1, 0) == 1 && area[page] == 'b');
    char byte;
    CHECK(pread(first, &byte, 1, page) == 1 && byte == 'b');
    CHECK(pread(second, area + page * 2, 1, 0) == -1 && errno == EFAULT);
    CHECK(pwrite(second, area + page * 2, 1, 0) == -1 && errno == EFAULT);
    CHECK(munmap(area, 3 * page) == 0 && munmap(private, page) == 0);
    CHECK(close(first) == 0 && close(second) == 0);
    puts("MEMFD_CASE lazy-pages-in-user-copy");
}

static void seals(void) {
    int fd = memory_file(), alias = dup(fd);
    CHECK(alias >= 0 && ftruncate(fd, page * 2) == 0);
    CHECK(fcntl(fd, F_ADD_SEALS, 0x4000) == -1 && errno == EINVAL);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW) == 0);
    CHECK(fcntl(alias, F_GET_SEALS) == (F_SEAL_SHRINK | F_SEAL_GROW));
    CHECK(ftruncate(alias, page) == -1 && errno == EPERM);
    CHECK(ftruncate(alias, page * 3) == -1 && errno == EPERM);
    CHECK(ftruncate(alias, page * 2) == 0);
    CHECK(pwrite(alias, "ab", 2, page * 2 - 1) == 1);
    CHECK(pwrite(alias, "b", 1, page * 2) == -1 && errno == EPERM);
    CHECK(pwrite(alias, "w", 1, page * 2 - 1) == 1);

    char* old = mmap(NULL, page, PROT_READ, MAP_SHARED, alias, 0);
    CHECK(old != MAP_FAILED);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == -1 && errno == EBUSY);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == 0);
    CHECK(pwrite(alias, "x", 1, 0) == -1 && errno == EPERM);
    int pipes[2];
    CHECK(pipe(pipes) == 0 && write(pipes[1], "z", 1) == 1);
    CHECK(splice(pipes[0], NULL, alias, NULL, 1, 0) == -1 && errno == EPERM);
    char readback;
    CHECK(read(pipes[0], &readback, 1) == 1 && readback == 'z');
    CHECK(close(pipes[0]) == 0 && close(pipes[1]) == 0);
    CHECK(mprotect(old, page, PROT_READ | PROT_WRITE) == 0);
    old[0] = 'y';
    CHECK(pread(fd, &readback, 1, 0) == 1 && readback == 'y');
    CHECK(mmap(NULL, page, PROT_WRITE, MAP_SHARED, fd, 0) == MAP_FAILED && errno == EPERM);
    char* fresh = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(fresh != MAP_FAILED && mprotect(fresh, page, PROT_READ | PROT_WRITE) == -1 &&
          errno == EACCES);
    CHECK(munmap(old, page) == 0 && munmap(fresh, page) == 0);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SEAL) == 0);
    CHECK(fcntl(alias, F_ADD_SEALS, 0) == -1 && errno == EPERM);
    CHECK(fcntl(alias, F_GET_SEALS) ==
          (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE));
    CHECK(close(fd) == 0 && close(alias) == 0);

    fd = memory_file();
    CHECK(ftruncate(fd, 2 * page - 1) == 0 && fcntl(fd, F_ADD_SEALS, F_SEAL_GROW) == 0);
    CHECK(pwrite(fd, "ab", 2, 2 * page - 2) == -1 && errno == EPERM);
    CHECK(pwrite(fd, "a", 1, 2 * page - 2) == 1);
    char* large = malloc(page + 1);
    CHECK(large);
    memset(large, 'g', page + 1);
    CHECK(pwrite(fd, large, page + 1, page - 1) == 1);
    CHECK(pread(fd, &readback, 1, page - 1) == 1 && readback == 'g');
    CHECK(pread(fd, &readback, 1, page) == 1 && readback == 0);
    free(large);
    CHECK(close(fd) == 0);
    puts("MEMFD_CASE seals");
}

static void pinned_pages(void) {
    int fd = memory_file();
    CHECK(ftruncate(fd, page) == 0 && pwrite(fd, "pin", 3, 0) == 3);
    void* mapping = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(mapping != MAP_FAILED);
    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    struct iovec io = {.iov_base = mapping, .iov_len = 3};
    CHECK(vmsplice(pipefd[1], &io, 1, 0) == 3);
    CHECK(munmap(mapping, page) == 0);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == -1 && errno == EBUSY);
    char actual[3];
    CHECK(read(pipefd[0], actual, sizeof(actual)) == 3 && !memcmp(actual, "pin", 3));
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == 0);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0 && close(fd) == 0);
    puts("MEMFD_CASE pipe-pinned-pages");
}

static void preallocation_and_punch(void) {
    int fd = memory_file();
    CHECK(fallocate(fd, 0, -1, page) == -1 && errno == EINVAL);
    CHECK(fallocate(fd, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(fallocate(fd, 0, INT64_MAX, 2) == -1 && errno == EFBIG);
    CHECK(fallocate(fd, FALLOC_FL_PUNCH_HOLE, 0, page) == -1 && errno == EOPNOTSUPP);

    CHECK(fallocate(fd, FALLOC_FL_KEEP_SIZE, 4 * page, page) == 0);
    struct stat info;
    CHECK(fstat(fd, &info) == 0 && info.st_size == 0 && info.st_blocks == (blkcnt_t)(page / 512));
    CHECK(posix_fallocate(fd, 0, 3 * page) == 0);
    CHECK(fstat(fd, &info) == 0 && info.st_size == (off_t)(3 * page));
    CHECK(info.st_blocks == (blkcnt_t)(4 * page / 512) && lseek(fd, 0, SEEK_CUR) == 0);
    char* shared = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char* private = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(shared != MAP_FAILED && private != MAP_FAILED);
    shared[page - 1] = 'l';
    shared[page - 2] = 'L';
    shared[page] = 'm';
    shared[2 * page] = 'r';
    shared[2 * page + 1] = 'R';
    private[page] = 'p';

    CHECK(fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, page - 1, page + 2) == 0);
    CHECK(fstat(fd, &info) == 0 && info.st_size == (off_t)(3 * page));
    CHECK(info.st_blocks == (blkcnt_t)(3 * page / 512));
    CHECK(shared[page - 2] == 'L' && shared[page - 1] == 0 && shared[page] == 0);
    CHECK(shared[2 * page] == 0 && shared[2 * page + 1] == 'R' && private[page] == 'p');
    CHECK(munmap(shared, 3 * page) == 0 && munmap(private, 3 * page) == 0);

    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_FUTURE_WRITE) == 0);
    CHECK(fallocate(fd, FALLOC_FL_KEEP_SIZE, 4 * page, page) == -1 && errno == EPERM);
    CHECK(fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, page, page) == -1 &&
          errno == EPERM);
    CHECK(close(fd) == 0);
    puts("MEMFD_CASE preallocation-and-hole-punch");
}

static void file_transfers(void) {
    int input = memory_file(), output = memory_file();
    CHECK(pwrite(input, "mapped data", 11, 0) == 11);
    off_t source = 7, target = 8195;
    CHECK(copy_file_range(input, &source, output, &target, 11, 0) == 4);
    CHECK(source == 11 && target == 8199);
    CHECK(lseek(input, 0, SEEK_CUR) == 0 && lseek(output, 0, SEEK_CUR) == 0);
    source = 0;
    CHECK(sendfile(output, input, &source, 11) == 11 && source == 11);
    char data[11];
    CHECK(pread(output, data, 11, 0) == 11 && !memcmp(data, "mapped data", 11));
    CHECK(pread(output, data, 4, 8195) == 4 && !memcmp(data, "data", 4));
    CHECK(fcntl(output, F_ADD_SEALS, F_SEAL_WRITE) == 0);
    source = 0;
    CHECK(copy_file_range(input, &source, output, &target, 3, 0) == -1 && errno == EPERM);
    CHECK(source == 0 && target == 8199);
    CHECK(close(input) == 0 && close(output) == 0);
    puts("MEMFD_CASE file-transfers");
}

static void mapping_resize(void) {
    for (int shared = 0; shared <= 1; ++shared) {
        int fd = memory_file();
        CHECK(ftruncate(fd, 4 * page) == 0);
        CHECK(pwrite(fd, "ABC", 1, page) == 1 && pwrite(fd, "B", 1, 2 * page) == 1 &&
              pwrite(fd, "C", 1, 3 * page) == 1);
        const int rw = PROT_READ | PROT_WRITE;
        const int anon = MAP_PRIVATE | MAP_ANONYMOUS;
        char* alias = mmap(NULL, 4 * page, rw, MAP_SHARED, fd, 0);
        char* hold = mmap(NULL, 5 * page, PROT_NONE, anon, -1, 0);
        CHECK(alias != MAP_FAILED && hold != MAP_FAILED);
        char* source = hold + page;
        char* blocker = source + 2 * page;
        int kind = shared ? MAP_SHARED : MAP_PRIVATE;
        CHECK(mmap(source, page, rw, kind | MAP_FIXED, fd, page) == source);
        CHECK(munmap(source + page, page) == 0);
        CHECK(mprotect(blocker, page, rw) == 0);
        blocker[0] = 'Z';
        CHECK(source[0] == 'A');
        source[0] = 'X';
        CHECK(mremap(source, page, 2 * page, 0) == source);
        CHECK(source[page] == 'B' && alias[page] == (shared ? 'X' : 'A'));
        CHECK(mremap(source, 2 * page, 3 * page, 0) == MAP_FAILED && errno == ENOMEM);
        struct rlimit saved, limit;
        CHECK(getrlimit(RLIMIT_AS, &saved) == 0);
        limit = (struct rlimit){1, saved.rlim_max};
        CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
        CHECK(mremap(source, 2 * page, 3 * page, MREMAP_MAYMOVE) == MAP_FAILED && errno == ENOMEM);
        CHECK(setrlimit(RLIMIT_AS, &saved) == 0);
        CHECK(source[0] == 'X' && source[page] == 'B' && blocker[0] == 'Z');
        char* moved = mremap(source, 2 * page, 3 * page, MREMAP_MAYMOVE);
        CHECK(moved != MAP_FAILED && moved != source);
        CHECK(moved[0] == 'X' && moved[page] == 'B' && moved[2 * page] == 'C');
        moved[2 * page] = 'Y';
        CHECK(alias[3 * page] == (shared ? 'Y' : 'C') && blocker[0] == 'Z');
        CHECK(mmap(source, 2 * page, rw, anon | MAP_FIXED_NOREPLACE, -1, 0) == source);
        CHECK(ftruncate(fd, 2 * page) == 0);
        expect_fault(moved + 2 * page, SIGBUS);
        CHECK(close(fd) == 0);
        CHECK(mremap(moved, 3 * page, page, 0) == moved && moved[0] == 'X');
        CHECK(mmap(moved + page, 2 * page, rw, anon | MAP_FIXED_NOREPLACE, -1, 0) == moved + page);
        CHECK(munmap(moved, 3 * page) == 0 && munmap(hold, 5 * page) == 0 &&
              munmap(alias, 4 * page) == 0);
    }
    puts("MEMFD_CASE mapping-resize");
}

static void executable_seals(int legacy) {
    int fd = memfd_create("noexec", MFD_NOEXEC_SEAL);
    if (legacy) {
        CHECK(fd == -1 && errno == EINVAL);
        puts("MEMFD_CASE executable-seals");
        return;
    }
    CHECK(fd >= 0 && fcntl(fd, F_GET_SEALS) == F_SEAL_EXEC);
    struct stat info;
    CHECK(fstat(fd, &info) == 0 && (info.st_mode & 0777) == 0666);
    CHECK(fchmod(fd, 0777) == -1 && errno == EPERM);
    CHECK(ftruncate(fd, page) == 0);
    void* executable = mmap(NULL, page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    CHECK(executable != MAP_FAILED);
    CHECK(*(const char*)executable == 0);
    CHECK(munmap(executable, page) == 0 && close(fd) == 0);

    fd = memfd_create("exec", MFD_ALLOW_SEALING | MFD_EXEC);
    CHECK(fd >= 0 && ftruncate(fd, page) == 0);
    CHECK(fcntl(fd, F_ADD_SEALS, F_SEAL_EXEC) == 0);
    CHECK(fcntl(fd, F_GET_SEALS) ==
          (F_SEAL_EXEC | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE | F_SEAL_SHRINK | F_SEAL_GROW));
    CHECK(ftruncate(fd, 0) == -1 && errno == EPERM);
    CHECK(pwrite(fd, "b", 1, 0) == -1 && errno == EPERM);
    CHECK(close(fd) == 0);
    puts("MEMFD_CASE executable-seals");
}

int main(int argc, char** argv) {
    if (argc == 4 && !strcmp(argv[1], "--exec-child")) {
        char data;
        CHECK(pread(atoi(argv[2]), &data, 1, 0) == 1 && data == 'e');
        CHECK(fcntl(atoi(argv[3]), F_GETFD) == -1 && errno == EBADF);
        return 0;
    }
    int legacy = 0;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--ordinary"))
            CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        else {
            CHECK(!strcmp(argv[i], "--legacy-memfd"));
            legacy = 1;
        }
    }
    const struct rlimit no_core = {0, 0};
    CHECK(setrlimit(RLIMIT_CORE, &no_core) == 0);
    page = (size_t)sysconf(_SC_PAGESIZE);
    CHECK(page == 4096);
    arguments();
    descriptor_exec(argv[0]);
    sparse_pages();
    mappings();
    mapping_faults();
    io_faulting_ranges();
    seals();
    pinned_pages();
    preallocation_and_punch();
    file_transfers();
    mapping_resize();
    executable_seals(legacy);
    printf("MEMFD_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/abi/abi.c
 * @brief   Linux userspace ABI smoke tests.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Exercises supported Linux system calls using the arguments and return
 * conventions expected by userspace.
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
#include <asm/prctl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/stat.h>

#ifndef ABI_LINKAGE
#define ABI_LINKAGE "static"
#endif
#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "ABI_FAIL line=%d: %s errno=%d (%s)\n", __LINE__, #expr, errno,        \
                    strerror(errno));                                                              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void child_status(pid_t child, int expected) {
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == expected);
}

static uintptr_t read_gs_base(void) {
    uintptr_t base = UINTPTR_MAX;
    CHECK(syscall(SYS_arch_prctl, ARCH_GET_GS, &base) == 0);
    return base;
}

static uint64_t read_gs_word(void) {
    uint64_t value;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(value) : : "memory");
    return value;
}

static void user_gs_base(const char* executable) {
    uintptr_t saved = read_gs_base();
    uintptr_t fs_before, fs_after;
    CHECK(syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_before) == 0);
    uint64_t parent_value = UINT64_C(0x123456789abcdef0);
    CHECK(syscall(SYS_arch_prctl, ARCH_SET_GS, &parent_value) == 0);
    CHECK(read_gs_base() == (uintptr_t)&parent_value && read_gs_word() == parent_value);
    CHECK(syscall(SYS_arch_prctl, ARCH_SET_GS, UINTPTR_MAX) == -1 && errno == EPERM);
    CHECK(syscall(SYS_arch_prctl, ARCH_GET_GS, 1ul) == -1 && errno == EFAULT);
    CHECK(read_gs_word() == parent_value);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(read_gs_base() == (uintptr_t)&parent_value && read_gs_word() == parent_value);
        uint64_t child_value = UINT64_C(0xb9876543210fedca);
        CHECK(syscall(SYS_arch_prctl, ARCH_SET_GS, &child_value) == 0);
        CHECK(read_gs_word() == child_value);
        execl(executable, executable, "verify-exec-gs", (char*)0);
        _exit(91);
    }
    child_status(child, 0);
    CHECK(read_gs_base() == (uintptr_t)&parent_value && read_gs_word() == parent_value);
    CHECK(syscall(SYS_arch_prctl, ARCH_GET_FS, &fs_after) == 0 && fs_after == fs_before);
    CHECK(syscall(SYS_arch_prctl, ARCH_SET_GS, saved) == 0);
    puts("ABI_USER_GS_BASE_PASS linkage=" ABI_LINKAGE);
}

static void shared_file_table_pressure(void) {
    enum { workers = 12, files_per_worker = 100 };

    for (unsigned round = 0; round < 8; ++round) {
        int ready[2], release[2];
        CHECK(pipe(ready) == 0 && pipe(release) == 0);
        pid_t children[workers];
        for (unsigned i = 0; i < workers; ++i) {
            children[i] = fork();
            CHECK(children[i] >= 0);
            if (children[i])
                continue;
            CHECK(close(ready[0]) == 0 && close(release[1]) == 0);
            int files[files_per_worker];
            for (unsigned j = 0; j < files_per_worker; ++j) {
                files[j] = open("/dev/null", O_RDONLY | O_CLOEXEC);
                CHECK(files[j] >= 0);
            }
            CHECK(write(ready[1], "+", 1) == 1 && close(ready[1]) == 0);
            char byte;
            CHECK(read(release[0], &byte, 1) == 0);
            if (round % 2 == 0)
                for (unsigned j = 0; j < files_per_worker; ++j)
                    CHECK(close(files[j]) == 0);
            _exit(0);
        }
        CHECK(close(ready[1]) == 0 && close(release[0]) == 0);
        char byte;
        for (unsigned i = 0; i < workers; ++i)
            CHECK(read(ready[0], &byte, 1) == 1 && byte == '+');
        int fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        CHECK(fd >= 0 && write(fd, "+", 1) == 1 && close(fd) == 0);
        CHECK(close(ready[0]) == 0 && close(release[1]) == 0);
        for (unsigned i = 0; i < workers; ++i)
            child_status(children[i], 0);
    }
    puts("ABI_OPEN_DESCRIPTION_PRESSURE_PASS linkage=" ABI_LINKAGE);
}

static void executable_path(const char* expected) {
    char path[256];
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path));
    CHECK(length == (ssize_t)strlen(expected) && !memcmp(path, expected, (size_t)length));
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    unsigned char magic[4];
    CHECK(fd >= 0 && read(fd, magic, sizeof(magic)) == sizeof(magic) &&
          !memcmp(magic, "\177ELF", sizeof(magic)) && close(fd) == 0);
}

static void executable_link(void) {
    static const char executable[] = "/bin/abi-" ABI_LINKAGE;
    static const char alias[] = "/bin/abi-exe-" ABI_LINKAGE;
    executable_path(executable);
    CHECK(link(executable, alias) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        executable_path(executable);
        int fd = open(alias, O_PATH | O_CLOEXEC);
        CHECK(fd >= 0);
        char* const arguments[] = {(char*)alias, "exe-alias", NULL};
        syscall(SYS_execveat, fd, "", arguments, environ, AT_EMPTY_PATH);
        CHECK(0);
    }
    child_status(child, 0);
    puts("ABI_PROC_EXE_PASS linkage=" ABI_LINKAGE);
}

static void proc_cmdline_child(char** argv) {
    static const char expected[] = "axiom app\0proc-cmdline\0\0two words";
    static const char title[] = "A rewritten process title that extends beyond the argument list";
    char actual[128];
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    CHECK(read(fd, actual, 5) == 5);
    CHECK(read(fd, actual + 5, sizeof(actual) - 5) == sizeof(expected) - 5);
    CHECK(!memcmp(actual, expected, sizeof(expected)) && read(fd, actual, 1) == 0);
    CHECK(environ[0] == argv[0] + sizeof(expected));
    argv[0][0] = 'A';
    CHECK(pread(fd, actual, 2, 0) == 2 && !memcmp(actual, "Ax", 2));
    CHECK(sizeof(title) <= sizeof(expected) + strlen(environ[0]) + 1);
    memcpy(argv[0], title, sizeof(title));
    CHECK(pread(fd, actual, sizeof(actual), 0) == sizeof(title));
    CHECK(!memcmp(actual, title, sizeof(title)) && close(fd) == 0);
}

static void proc_cmdline(const char* binary) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char* const args[] = {"axiom app", "proc-cmdline", "", "two words", NULL};
        char* const env[] = {"PROBE_ENV=abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz",
                             NULL};
        execve(binary, args, env);
        CHECK(0);
    }
    child_status(child, 0);
    puts("ABI_PROC_CMDLINE_PASS linkage=" ABI_LINKAGE);
}

struct proc_usage {
    uint64_t cpu_ticks, virtual_bytes, resident_pages;
};

static struct proc_usage read_proc_usage(void) {
    char data[640] = {0};
    int fd = open("/proc/self/stat", O_RDONLY);
    CHECK(fd >= 0 && read(fd, data, sizeof(data) - 1) > 0 && close(fd) == 0);
    char* end_name = strrchr(data, ')');
    CHECK(end_name && end_name[1] == ' ' && end_name[3] == ' ');
    char* cursor = end_name + 4;
    struct proc_usage usage = {0};
    for (unsigned field = 4; field <= 24; ++field) {
        char* end;
        uint64_t value = strtoull(cursor, &end, 10);
        CHECK(end > cursor && *end == ' ');
        cursor = end + 1;
        if (field == 14 || field == 15)
            usage.cpu_ticks += value;
        else if (field == 23)
            usage.virtual_bytes = value;
        else if (field == 24)
            usage.resident_pages = value;
    }
    return usage;
}

static void proc_usage(void) {
    const size_t size = 16 * 1024 * 1024;
    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    CHECK(page == 4096);
    struct proc_usage initial = read_proc_usage();
    volatile char* mapping =
        mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    for (size_t i = 0; i < size; i += page)
        mapping[i] = 'A';
    struct timespec started, sample;
    CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &started) == 0);
    do {
        for (unsigned i = 0; i < 50000; ++i)
            __asm__ volatile("" ::: "memory");
        CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &sample) == 0);
    } while ((sample.tv_sec - started.tv_sec) * INT64_C(1000000000) + sample.tv_nsec -
                 started.tv_nsec <
             150000000);
    struct proc_usage used = read_proc_usage();
    CHECK(used.cpu_ticks > initial.cpu_ticks);
    CHECK(used.virtual_bytes >= initial.virtual_bytes + size);
    CHECK(used.resident_pages >= initial.resident_pages + size / (2 * page));
    CHECK(munmap((void*)mapping, size) == 0);
    struct proc_usage released = read_proc_usage();
    CHECK(released.virtual_bytes <= used.virtual_bytes - size);
    CHECK(released.resident_pages + size / (2 * page) <= used.resident_pages);
    puts("ABI_PROC_USAGE_PASS linkage=" ABI_LINKAGE);
}

static void anonymous_address_reservations(void) {
    const size_t length = 2044ull * 1024 * 1024;
    const size_t page = 4096;
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    int status;
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct rlimit limit;
        CHECK(getrlimit(RLIMIT_AS, &limit) == 0);
        limit.rlim_cur = 128 * 1024 * 1024;
        CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
        CHECK(mmap(NULL, length, PROT_NONE, flags, -1, 0) == MAP_FAILED && errno == ENOMEM);
        _exit(0);
    }
    child_status(child, 0);

    struct proc_usage before = read_proc_usage();
    void* hint = (void*)0x200000000000ull;
    unsigned char* arena = mmap(hint, length, PROT_NONE, flags, -1, 0);
    CHECK(arena == hint);
    struct proc_usage reserved = read_proc_usage();
    CHECK(reserved.virtual_bytes >= before.virtual_bytes + length);
    CHECK(reserved.resident_pages <= before.resident_pages + 256);
    CHECK(mmap(arena + page, page, PROT_READ, flags | MAP_FIXED_NOREPLACE, -1, 0) == MAP_FAILED &&
          errno == EEXIST);

    CHECK(mprotect(arena, page, PROT_READ | PROT_WRITE) == 0 && arena[0] == 0);
    arena[0] = 'P';
    unsigned char* tail = arena + length - page;
    CHECK(mprotect(tail, page, PROT_READ | PROT_WRITE) == 0);
    int ends[2];
    CHECK(pipe(ends) == 0 && write(ends[1], "pass", 4) == 4 && read(ends[0], tail, 4) == 4);
    CHECK(memcmp(tail, "pass", 4) == 0);
    CHECK(close(ends[0]) == 0 && close(ends[1]) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(arena[0] == 'P' && mprotect(arena + page, page, PROT_READ | PROT_WRITE) == 0);
        CHECK(arena[page] == 0);
        arena[0] = 'C';
        _exit(0);
    }
    child_status(child, 0);
    CHECK(arena[0] == 'P');
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        volatile const unsigned char* inaccessible = arena + page;
        _exit(inaccessible[0]);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
          WTERMSIG(status) == SIGSEGV);

    // Commit and execute one page, then replace it with a fresh reservation.
    unsigned char* code = arena + 2 * page;
    CHECK(mmap(code, page, PROT_READ | PROT_WRITE, flags | MAP_FIXED, -1, 0) == code);
    const unsigned char machine_code[] = {0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 42, 0, 0, 0, 0xc3};
    memcpy(code, machine_code, sizeof(machine_code));
    CHECK(mprotect(code, page, PROT_READ | PROT_EXEC) == 0);
    int (*call)(void) = (void*)code;
    CHECK(call() == 42);
    CHECK(mmap(code, page, PROT_NONE, flags | MAP_FIXED, -1, 0) == code);
    CHECK(mprotect(code, page, PROT_READ) == 0 && code[0] == 0);
    CHECK(munmap(arena, length) == 0);
    CHECK(read_proc_usage().virtual_bytes <= reserved.virtual_bytes - length);

    unsigned char* small = mmap(hint, page, PROT_READ | PROT_WRITE, flags, -1, 0);
    CHECK(small != MAP_FAILED);
    small[0] = 'M';
    small = mremap(small, page, 2 * page, MREMAP_MAYMOVE);
    CHECK(small != MAP_FAILED && small[0] == 'M' && small[page] == 0);
    CHECK(munmap(small, 2 * page) == 0);
    puts("ABI_ANONYMOUS_RESERVATION_PASS linkage=" ABI_LINKAGE);
}

static void seqpacket_pair(void) {
    int pair[2], type = 0, enabled = 1;
    socklen_t length = sizeof(type);
    CHECK(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
    CHECK(getsockopt(pair[0], SOL_SOCKET, SO_TYPE, &type, &length) == 0 && type == SOCK_SEQPACKET);
    CHECK(fcntl(pair[1], F_GETFD) == FD_CLOEXEC && (fcntl(pair[1], F_GETFL) & O_NONBLOCK));
    CHECK(setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) == 0);
    struct sockaddr_un ignored = {.sun_family = AF_UNIX, .sun_path = "/missing-axiom-seqpacket"};
    CHECK(sendto(pair[0], "hello", 5, MSG_EOR, (struct sockaddr*)&ignored, sizeof(ignored)) == 5);
    CHECK(write(pair[0], "two", 3) == 3);
    char actual[16];
    struct iovec vector = {.iov_base = actual, .iov_len = 2};

    union {
        struct cmsghdr alignment;
        char bytes[CMSG_SPACE(sizeof(struct ucred))];
    } control;
    struct sockaddr_un address;
    struct msghdr message = {.msg_name = &address,
                             .msg_namelen = sizeof(address),
                             .msg_iov = &vector,
                             .msg_iovlen = 1,
                             .msg_control = control.bytes,
                             .msg_controllen = sizeof(control.bytes)};
    CHECK(recvmsg(pair[1], &message, MSG_PEEK | MSG_TRUNC) == 5);
    CHECK(!memcmp(actual, "he", 2) && (message.msg_flags & MSG_TRUNC) && !message.msg_namelen);
    struct cmsghdr* header = CMSG_FIRSTHDR(&message);
    CHECK(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_CREDENTIALS);
    struct ucred credentials;
    memcpy(&credentials, CMSG_DATA(header), sizeof(credentials));
    CHECK(credentials.pid == getpid() && credentials.uid == getuid() &&
          credentials.gid == getgid());
    CHECK(recv(pair[1], actual, sizeof(actual), 0) == 5 && !memcmp(actual, "hello", 5));
    CHECK(read(pair[1], actual, sizeof(actual)) == 3 && !memcmp(actual, "two", 3));
    CHECK(recv(pair[1], actual, sizeof(actual), 0) == -1 && errno == EAGAIN);
    CHECK(send(pair[0], "", 0, 0) == 0 && recv(pair[1], actual, sizeof(actual), 0) == 0);

    enabled = 0;
    CHECK(setsockopt(pair[1], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) == 0);
    int file = open("/dev/null", O_RDONLY);
    CHECK(file >= 0);
    vector.iov_len = 1;
    actual[0] = 'F';
    message.msg_name = NULL;
    message.msg_namelen = 0;
    message.msg_controllen = CMSG_SPACE(sizeof(file));
    header = CMSG_FIRSTHDR(&message);
    CHECK(header);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(file));
    memcpy(CMSG_DATA(header), &file, sizeof(file));
    CHECK(sendmsg(pair[0], &message, 0) == 1 && close(file) == 0);
    CHECK(recvmsg(pair[1], &message, MSG_CMSG_CLOEXEC) == 1 && actual[0] == 'F');
    header = CMSG_FIRSTHDR(&message);
    CHECK(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS);
    memcpy(&file, CMSG_DATA(header), sizeof(file));
    CHECK(fcntl(file, F_GETFD) == FD_CLOEXEC && read(file, actual, 1) == 0 && close(file) == 0);

    CHECK(shutdown(pair[0], SHUT_WR) == 0);
    struct pollfd ready = {.fd = pair[1], .events = POLLIN | POLLRDHUP};
    CHECK(poll(&ready, 1, 0) == 1 && ready.revents == (POLLIN | POLLRDHUP));
    CHECK(recv(pair[1], actual, sizeof(actual), 0) == 0);
    CHECK(send(pair[1], "reply", 5, 0) == 5 && recv(pair[0], actual, sizeof(actual), 0) == 5);
    CHECK(close(pair[0]) == 0);
    CHECK(poll(&ready, 1, 0) == 1 && ready.revents == (POLLIN | POLLRDHUP | POLLHUP));
    CHECK(send(pair[1], "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    CHECK(close(pair[1]) == 0);
}

static void seqpacket_listener(void) {
    int listener = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    int client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    CHECK(listener >= 0 && client >= 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int name = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1, "seqpacket-%ld",
                        (long)getpid());
    CHECK(name > 0 && (size_t)name < sizeof(address.sun_path) - 1);
    socklen_t size = offsetof(struct sockaddr_un, sun_path) + 1 + name;
    CHECK(bind(listener, (struct sockaddr*)&address, size) == 0 && listen(listener, 4) == 0);
    CHECK(connect(client, (struct sockaddr*)&address, size) == 0);
    CHECK(send(client, "before accept", 13, 0) == 13);
    int server = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    char actual[32];
    CHECK(server >= 0 && read(server, actual, sizeof(actual)) == 13);
    CHECK(!memcmp(actual, "before accept", 13));
    CHECK(close(server) == 0 && close(client) == 0 && close(listener) == 0);
    puts("ABI_UNIX_SEQPACKET_PASS linkage=" ABI_LINKAGE);
}

static void extended_metadata(int directory, int fd) {
    struct stat old;
    struct statx info;
    CHECK(fstat(fd, &old) == 0);
    CHECK(syscall(SYS_statx, directory, "alias", AT_NO_AUTOMOUNT, STATX_BASIC_STATS | STATX_MNT_ID,
                  &info) == 0);
    CHECK((info.stx_mask & (STATX_BASIC_STATS | STATX_MNT_ID)) ==
          (STATX_BASIC_STATS | STATX_MNT_ID));
    CHECK(info.stx_ino == old.st_ino && info.stx_mode == old.st_mode &&
          info.stx_uid == old.st_uid && info.stx_gid == old.st_gid &&
          info.stx_nlink == old.st_nlink && info.stx_size == (uint64_t)old.st_size &&
          info.stx_blocks == (uint64_t)old.st_blocks && info.stx_blksize == old.st_blksize);
    CHECK(info.stx_atime.tv_sec == old.st_atim.tv_sec &&
          info.stx_atime.tv_nsec == old.st_atim.tv_nsec &&
          info.stx_mtime.tv_sec == old.st_mtim.tv_sec &&
          info.stx_mtime.tv_nsec == old.st_mtim.tv_nsec &&
          info.stx_ctime.tv_sec == old.st_ctim.tv_sec &&
          info.stx_ctime.tv_nsec == old.st_ctim.tv_nsec);
    CHECK(info.stx_dev_major == major(old.st_dev) && info.stx_dev_minor == minor(old.st_dev) &&
          info.stx_mnt_id != 0);
    CHECK(syscall(SYS_statx, directory, "alias", AT_SYMLINK_NOFOLLOW, STATX_TYPE, &info) == 0 &&
          (info.stx_mask & STATX_TYPE) && S_ISLNK(info.stx_mode));
    int path = openat(directory, "file", O_PATH | O_CLOEXEC);
    CHECK(path >= 0);
    CHECK(syscall(SYS_statx, path, "", AT_EMPTY_PATH, STATX_INO, &info) == 0 &&
          (info.stx_mask & STATX_INO) && info.stx_ino == old.st_ino);
    CHECK(close(path) == 0);
    CHECK(syscall(SYS_statx, AT_FDCWD, "/dev/null", 0, STATX_TYPE, &info) == 0 &&
          S_ISCHR(info.stx_mode) && info.stx_rdev_major == 1 && info.stx_rdev_minor == 3);
    CHECK(syscall(SYS_statx, AT_FDCWD, "/", 0, STATX_BASIC_STATS, &info) == 0 &&
          (info.stx_attributes_mask & STATX_ATTR_MOUNT_ROOT) &&
          (info.stx_attributes & STATX_ATTR_MOUNT_ROOT));
    CHECK(syscall(SYS_statx, directory, "absent", 0, STATX_TYPE, &info) == -1 && errno == ENOENT);
    CHECK(syscall(SYS_statx, fd, "", 0, STATX_TYPE, &info) == -1 && errno == ENOENT);
    CHECK(syscall(SYS_statx, fd, "child", 0, STATX_TYPE, &info) == -1 && errno == ENOTDIR);
    CHECK(syscall(SYS_statx, -1, "", AT_EMPTY_PATH, STATX_TYPE, &info) == -1 && errno == EBADF);
    CHECK(syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX__RESERVED, &info) == -1 &&
          errno == EINVAL);
    CHECK(syscall(SYS_statx, fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_TYPE, STATX_TYPE, &info) == -1 &&
          errno == EINVAL);
    CHECK(syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_TYPE, NULL) == -1 && errno == EFAULT);
    puts("ABI_STATX_PASS linkage=" ABI_LINKAGE);
}

static void proc_system_stats(void) {
    struct sysinfo system;
    CHECK(sysinfo(&system) == 0);
    FILE* file = fopen("/proc/meminfo", "r");
    unsigned long long total, free, available;
    CHECK(file && fscanf(file, "MemTotal: %llu kB\nMemFree: %llu kB\nMemAvailable: %llu kB", &total,
                         &free, &available) == 3);
    CHECK(total == (uint64_t)system.totalram * system.mem_unit / 1024 && free == available &&
          available <= total && fclose(file) == 0);

    file = fopen("/proc/stat", "r");
    char aggregate[256], core[256];
    CHECK(file && fgets(aggregate, sizeof(aggregate), file) && fgets(core, sizeof(core), file));
    CHECK(!strncmp(aggregate, "cpu  ", 5) && !strncmp(core, "cpu0 ", 5) &&
          !strcmp(aggregate + 5, core + 5) && fclose(file) == 0);
    unsigned long long user, nice, kernel, idle;
    CHECK(sscanf(core + 5, "%llu %llu %llu %llu", &user, &nice, &kernel, &idle) == 4 &&
          user + kernel + idle > 0 && !nice);

    file = fopen("/proc/uptime", "r");
    unsigned long long seconds, idle_seconds;
    unsigned centiseconds, idle_centiseconds;
    CHECK(file &&
          fscanf(file, "%llu.%2u %llu.%2u", &seconds, &centiseconds, &idle_seconds,
                 &idle_centiseconds) == 4 &&
          fclose(file) == 0);
    CHECK(seconds * 100 + centiseconds >= idle_seconds * 100 + idle_centiseconds);
    CHECK(idle_seconds * 100 + idle_centiseconds >= idle);

    file = fopen("/proc/cpuinfo", "r");
    char label[64];
    unsigned processor;
    CHECK(file && fscanf(file, "%63s : %u", label, &processor) == 2 &&
          !strcmp(label, "processor") && processor == 0 && fclose(file) == 0);
    puts("ABI_PROC_SYSTEM_PASS linkage=" ABI_LINKAGE);
}

static void proc_mount_inventory(void) {
    static const char path[] = "/tmp/abi mounts";
    char data[2048];
    ssize_t length = readlink("/proc/mounts", data, sizeof(data));
    CHECK(length == 11 && !memcmp(data, "self/mounts", 11));

    int fd = open("/proc/filesystems", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && (length = read(fd, data, sizeof(data) - 1)) > 0 && close(fd) == 0);
    data[length] = 0;
    CHECK(strstr(data, "nodev\tproc\n") && strstr(data, "\text2\n"));

    CHECK(mkdir(path, 0700) == 0);
    CHECK(mount("ramfs", path, "ramfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0);
    fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && (length = read(fd, data, sizeof(data) - 1)) > 0 && close(fd) == 0);
    data[length] = 0;
    CHECK(strstr(data, "proc /proc proc rw") &&
          strstr(data, "ramfs /tmp/abi\\040mounts ramfs rw,nosuid,nodev,noexec 0 0\n"));
    CHECK(umount(path) == 0 && rmdir(path) == 0);
    fd = open("/proc/self/mounts", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0 && (length = read(fd, data, sizeof(data) - 1)) > 0 && close(fd) == 0);
    data[length] = 0;
    CHECK(!strstr(data, "/tmp/abi\\040mounts"));
    puts("ABI_PROC_MOUNTS_PASS linkage=" ABI_LINKAGE);
}

static void relative_modes(void) {
    CHECK(mkdir("/tmp/abi-chmod", 0700) == 0);
    int parent = open("/tmp/abi-chmod", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(parent >= 0);
    int file = openat(parent, "file", O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(file >= 0);
    CHECK(fchmodat(parent, "file", 0640, 0) == 0);
    struct stat information;
    CHECK(fstat(file, &information) == 0 && S_ISREG(information.st_mode) &&
          (information.st_mode & 07777) == 0640);
    CHECK(symlinkat("file", parent, "alias") == 0);
    extended_metadata(parent, file);
    CHECK(fchmodat(parent, "alias", 0610, 0) == 0);
    CHECK(fstat(file, &information) == 0 && (information.st_mode & 07777) == 0610);
    CHECK(fstatat(parent, "alias", &information, AT_SYMLINK_NOFOLLOW) == 0 &&
          S_ISLNK(information.st_mode));
    CHECK(fchmodat(999, "/tmp/abi-chmod/file", 0660, 0) == 0);
    CHECK(fstat(file, &information) == 0 && (information.st_mode & 07777) == 0660);
    CHECK(fchmodat(999, "file", 0600, 0) == -1 && errno == EBADF);
    CHECK(fchmodat(file, "file", 0600, 0) == -1 && errno == ENOTDIR);
    CHECK(fchmodat(parent, "file/child", 0600, 0) == -1 && errno == ENOTDIR);
    CHECK(fchmodat(parent, "missing", 0600, 0) == -1 && errno == ENOENT);
    CHECK(symlinkat("loop", parent, "loop") == 0);
    CHECK(fchmodat(parent, "loop", 0600, 0) == -1 && errno == ELOOP);
    CHECK(unlinkat(parent, "loop", 0) == 0);
    CHECK(syscall(SYS_fchmodat, parent, (void*)(uintptr_t)0xffff800000000000, 0600) == -1 &&
          errno == EFAULT);
    CHECK(fchmodat(AT_FDCWD, "/tmp/abi-chmod", 0750, 0) == 0);
    CHECK(fstat(parent, &information) == 0 && S_ISDIR(information.st_mode) &&
          (information.st_mode & 07777) == 0750);
    CHECK(unlinkat(parent, "alias", 0) == 0 && unlinkat(parent, "file", 0) == 0);
    CHECK(close(file) == 0 && close(parent) == 0 && rmdir("/tmp/abi-chmod") == 0);
    puts("ABI_RELATIVE_MODES_PASS linkage=" ABI_LINKAGE);
}

int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "verify-exec-gs"))
        return read_gs_base() != 0;
    if (argc > 1 && !strcmp(argv[1], "child"))
        return 17;
    if (argc == 4 && !strcmp(argv[1], "proc-cmdline")) {
        proc_cmdline_child(argv);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "exe-alias")) {
        static const char moved[] = "/bin/abi-exe-renamed-" ABI_LINKAGE;
        executable_path(argv[0]);
        CHECK(rename(argv[0], moved) == 0);
        executable_path(moved);
        CHECK(unlink(moved) == 0);
        executable_path("/bin/abi-exe-renamed-" ABI_LINKAGE " (deleted)");
        return 0;
    }
    struct utsname name;
    CHECK(uname(&name) == 0);
    CHECK(!strcmp(name.sysname, "Axiom64"));
    CHECK(getpid() > 0);
    CHECK(getuid() == 0);
    CHECK(syscall(SYS_gettid) == getpid());
    errno = 0;
    CHECK(syscall(999) == -1 && errno == ENOSYS);
    CHECK(syscall(SYS_write, 1, (void*)(uintptr_t)0xffff800000000000, 4) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_read, 999, (void*)0, 1) == -1 && errno == EBADF);
    CHECK(syscall(SYS_write, 1, (void*)(uintptr_t)0x7ffffffffffe, 8) == -1 && errno == EFAULT);
    relative_modes();
    executable_link();
    proc_cmdline(argv[0]);
    proc_usage();
    seqpacket_pair();
    seqpacket_listener();
    proc_system_stats();
    proc_mount_inventory();

    char* memory = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED);
    strcpy(memory, "private memory");
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(!strcmp(memory, "private memory"));
        memory[0] = 'x';
        _exit(42);
    }
    child_status(child, 42);
    CHECK(memory[0] == 'p');
    CHECK(mprotect(memory, 8192, PROT_READ) == 0);
    CHECK(syscall(SYS_read, 0, memory, 1) == -1 && errno == EFAULT);
    CHECK(munmap(memory, 8192) == 0);
    CHECK(syscall(SYS_write, 1, memory, 1) == -1 && errno == EFAULT);

    int fd = open("/tmp/abi-file", O_CREAT | O_TRUNC | O_RDWR, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, "abcdefgh", 8) == 8);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    char buffer[32] = {0};
    CHECK(read(fd, buffer, 8) == 8);
    CHECK(!memcmp(buffer, "abcdefgh", 8));
    CHECK(pwrite(fd, "XY", 2, 3) == 2);
    CHECK(pread(fd, buffer, 8, 0) == 8);
    CHECK(!memcmp(buffer, "abcXYfgh", 8));
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == 8 && S_ISREG(st.st_mode));
    struct timespec file_times[2] = {{123, 456}, {124, 789}};
    CHECK(futimens(fd, file_times) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_atim.tv_sec == 123 && st.st_atim.tv_nsec == 456 &&
          st.st_mtim.tv_sec == 124 && st.st_mtim.tv_nsec == 789);
    file_times[0].tv_nsec = UTIME_OMIT;
    file_times[1] = (struct timespec){125, 999};
    CHECK(utimensat(AT_FDCWD, "/tmp/abi-file", file_times, 0) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_atim.tv_sec == 123 && st.st_mtim.tv_sec == 125 &&
          st.st_mtim.tv_nsec == 999);
    CHECK(ftruncate(fd, 3) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 3);
    CHECK(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC);
    int second = dup(fd);
    CHECK(second >= 0);
    CHECK(fcntl(second, F_GETFD) == 0);
    CHECK(close(second) == 0);
    CHECK(close(fd) == 0);
    CHECK(stat("/tmp/abi-file", &st) == 0);
    CHECK(unlink("/tmp/abi-file") == 0);

    fd = open("/tmp/link-original", O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, "linked", 6) == 6);
    CHECK(link("/tmp/link-original", "/tmp/link-alias") == 0);
    struct stat alias;
    CHECK(stat("/tmp/link-original", &st) == 0 && st.st_nlink == 2);
    CHECK(stat("/tmp/link-alias", &alias) == 0 && alias.st_ino == st.st_ino);
    CHECK(unlink("/tmp/link-original") == 0);
    CHECK(stat("/tmp/link-alias", &st) == 0 && st.st_nlink == 1);
    second = open("/tmp/link-alias", O_RDWR);
    CHECK(second >= 0);
    CHECK(pwrite(second, "L", 1, 0) == 1);
    CHECK(pread(fd, buffer, 6, 0) == 6 && !memcmp(buffer, "Linked", 6));
    CHECK(unlink("/tmp/link-alias") == 0);
    CHECK(pread(fd, buffer, 6, 0) == 6);
    close(second);
    close(fd);

    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(pipefd[0]);
        CHECK(write(pipefd[1], "pipe-data", 9) == 9);
        close(pipefd[1]);
        _exit(0);
    }
    close(pipefd[1]);
    memset(buffer, 0, sizeof(buffer));
    CHECK(read(pipefd[0], buffer, 9) == 9);
    CHECK(!strcmp(buffer, "pipe-data"));
    CHECK(read(pipefd[0], buffer, 1) == 0);
    close(pipefd[0]);
    child_status(child, 0);

    child = fork();
    CHECK(child >= 0);
    if (!child) {
        execl(argv[0], argv[0], "child", (char*)0);
        _exit(99);
    }
    child_status(child, 17);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        char* args[] = {"missing", 0};
        CHECK(execv("/does-not-exist", args) == -1 && errno == ENOENT);
        _exit(23);
    }
    child_status(child, 23);

    DIR* dir = opendir("/bin");
    CHECK(dir != 0);
    int entries = 0;
    while (readdir(dir))
        entries++;
    CHECK(entries > 4);
    CHECK(closedir(dir) == 0);
    CHECK(mkdir("/tmp/abi-dir", 0755) == 0);
    CHECK(chdir("/tmp/abi-dir") == 0);
    CHECK(getcwd(buffer, sizeof(buffer)) == buffer && !strcmp(buffer, "/tmp/abi-dir"));
    CHECK(chdir("/") == 0);
    CHECK(rmdir("/tmp/abi-dir") == 0);

    struct timespec before, after, delay = {0, 20000000};
    CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
    CHECK(nanosleep(&delay, 0) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
    CHECK(after.tv_sec > before.tv_sec || after.tv_nsec >= before.tv_nsec + 20000000);
    shared_file_table_pressure();
    anonymous_address_reservations();
    user_gs_base(argv[0]);
    puts("ABI_TESTS_PASS linkage=" ABI_LINKAGE);
    return 0;
}

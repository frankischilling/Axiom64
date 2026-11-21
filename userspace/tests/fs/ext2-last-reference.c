// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext2-last-reference.c
 * @brief   Check reclamation on the last ext-family inode reference.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Exercises final descriptor, mapping, task, pathname, executable and socket ownership.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(test)                                                                              \
    do {                                                                                           \
        if (!(test)) {                                                                             \
            printf("EXT2_LAST_REFERENCE_FAIL line=%d errno=%d %s\n", __LINE__, errno, #test);      \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

#ifndef TOP
#define TOP "/mnt"
#endif

static int free_delta(const struct statfs* before, fsfilcnt_t inodes, fsblkcnt_t blocks) {
    struct statfs after;
    REQUIRE(statfs(TOP, &after) == 0);
    REQUIRE(after.f_ffree == before->f_ffree + inodes);
    REQUIRE(after.f_bfree == before->f_bfree + blocks);
    return 0;
}

static int separate_descriptions(void) {
    int fd = open(TOP "/first", O_RDWR | O_CREAT | O_EXCL, 0600);
    REQUIRE(fd >= 0 && write(fd, "keep", 4) == 4);
    REQUIRE(link(TOP "/first", TOP "/alias") == 0);
    int alias = open(TOP "/alias", O_RDONLY);
    int second = dup(fd);
    REQUIRE(second >= 0 && alias >= 0);
    REQUIRE(unlink(TOP "/first") == 0 && unlink(TOP "/alias") == 0);
    struct statfs held;
    REQUIRE(statfs(TOP, &held) == 0);
    REQUIRE(close(fd) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(close(second) == 0 && free_delta(&held, 0, 0) == 0);
    char data[4];
    REQUIRE(read(alias, data, sizeof(data)) == sizeof(data) && !memcmp(data, "keep", 4));
    REQUIRE(close(alias) == 0 && free_delta(&held, 1, 1) == 0);
    return 0;
}

static int wait_success(pid_t child) {
    int status;
    REQUIRE(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

static int split_mapping(size_t page) {
    static const char path[] = TOP "/split-map";
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    REQUIRE(fd >= 0 && pwrite(fd, "a", 1, 0) == 1 && pwrite(fd, "b", 1, page) == 1 &&
            pwrite(fd, "c", 1, 2 * page) == 1);
    char* map = mmap(NULL, 3 * page, PROT_READ, MAP_PRIVATE, fd, 0);
    REQUIRE(map != MAP_FAILED);
    struct statfs held;
    REQUIRE(unlink(path) == 0 && statfs(TOP, &held) == 0 && close(fd) == 0);
    REQUIRE(free_delta(&held, 0, 0) == 0 && map[0] == 'a' && map[2 * page] == 'c');
    REQUIRE(munmap(map + page, page) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(mprotect(map + 2 * page, page, PROT_NONE) == 0);
    REQUIRE(umount(TOP) == -1 && errno == EBUSY);
    int memory = memfd_create("mapping-hole", MFD_CLOEXEC);
    REQUIRE(memory >= 0 && ftruncate(memory, page) == 0 && write(memory, "m", 1) == 1);
    char* middle = mmap(map + page, page, PROT_READ, MAP_SHARED | MAP_FIXED, memory, 0);
    REQUIRE(middle == map + page && close(memory) == 0);

    int gate[2];
    REQUIRE(pipe(gate) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (!child) {
        char command;
        close(gate[1]);
        _exit(read(gate[0], &command, 1) != 1 || command != 'r' ||
              mprotect(map + 2 * page, page, PROT_READ) || map[0] != 'a' || *middle != 'm' ||
              map[2 * page] != 'c');
    }
    REQUIRE(close(gate[0]) == 0);
    char* replacement =
        mmap(map + 2 * page, page, PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    REQUIRE(replacement == map + 2 * page && !*replacement && free_delta(&held, 0, 0) == 0);
    REQUIRE(munmap(map, 3 * page) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(write(gate[1], "r", 1) == 1 && close(gate[1]) == 0 && wait_success(child) == 0);
    REQUIRE(free_delta(&held, 1, 3) == 0);
    return 0;
}

static int replace_mapping(size_t page) {
    static const char path[] = TOP "/replaced-map";
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    REQUIRE(fd >= 0 && write(fd, "w", 1) == 1);
    char* map = mmap(NULL, page, PROT_NONE, MAP_PRIVATE, fd, 0);
    REQUIRE(map != MAP_FAILED);
    struct statfs held;
    REQUIRE(unlink(path) == 0 && statfs(TOP, &held) == 0 && close(fd) == 0);
    REQUIRE(free_delta(&held, 0, 0) == 0);
    REQUIRE(mmap(map, page, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_ANONYMOUS, -1, 0) ==
                MAP_FAILED &&
            errno == EEXIST && free_delta(&held, 0, 0) == 0);
    char* replacement = mmap(map, page, PROT_READ, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    REQUIRE(replacement == map && !*replacement && free_delta(&held, 1, 1) == 0);
    REQUIRE(munmap(replacement, page) == 0);
    return 0;
}

static int inherited_description(void) {
    int fd = open(TOP "/child-file", O_RDWR | O_CREAT | O_EXCL, 0600);
    int gate[2];
    REQUIRE(fd >= 0 && write(fd, "stay", 4) == 4 && pipe(gate) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (!child) {
        char command, data[4];
        close(gate[1]);
        _exit(read(gate[0], &command, 1) != 1 || pread(fd, data, sizeof(data), 0) != sizeof(data) ||
              memcmp(data, "stay", 4));
    }
    REQUIRE(close(gate[0]) == 0 && unlink(TOP "/child-file") == 0);
    struct statfs held;
    REQUIRE(statfs(TOP, &held) == 0 && close(fd) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(write(gate[1], "x", 1) == 1 && close(gate[1]) == 0 && wait_success(child) == 0);
    REQUIRE(free_delta(&held, 1, 1) == 0);
    return 0;
}

static int directory_pins(void) {
    REQUIRE(mkdir(TOP "/parent", 0700) == 0 && mkdir(TOP "/parent/child", 0700) == 0);
    REQUIRE(chdir(TOP "/parent/child") == 0);
    int root = open(TOP, O_RDONLY | O_DIRECTORY);
    int directory = open(".", O_RDONLY | O_DIRECTORY);
    REQUIRE(root >= 0 && directory >= 0);
    REQUIRE(rmdir(TOP "/parent/child") == 0 && rmdir(TOP "/parent") == 0);
    struct statfs held;
    REQUIRE(statfs(TOP, &held) == 0);
    REQUIRE(close(directory) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(fchdir(root) == 0 && free_delta(&held, 2, 2) == 0);
    REQUIRE(chdir("/") == 0 && close(root) == 0);
    return 0;
}

static int passed_description(void) {
    int sockets[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) == 0);
    int fd = open(TOP "/passed", O_RDWR | O_CREAT | O_EXCL, 0600);
    REQUIRE(fd >= 0 && write(fd, "held", 4) == 4);
    char marker = 'r';
    struct iovec vector = {&marker, 1};

    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr message = {0};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    struct cmsghdr* rights = CMSG_FIRSTHDR(&message);
    rights->cmsg_level = SOL_SOCKET;
    rights->cmsg_type = SCM_RIGHTS;
    rights->cmsg_len = CMSG_LEN(sizeof(fd));
    memcpy(CMSG_DATA(rights), &fd, sizeof(fd));
    REQUIRE(sendmsg(sockets[0], &message, 0) == 1 && unlink(TOP "/passed") == 0);
    struct statfs held;
    REQUIRE(statfs(TOP, &held) == 0 && close(fd) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(close(sockets[0]) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(recvmsg(sockets[1], &message, 0) == 1 && !(message.msg_flags & MSG_CTRUNC));
    rights = CMSG_FIRSTHDR(&message);
    REQUIRE(rights && rights->cmsg_len == CMSG_LEN(sizeof(fd)) &&
            rights->cmsg_level == SOL_SOCKET && rights->cmsg_type == SCM_RIGHTS);
    memcpy(&fd, CMSG_DATA(rights), sizeof(fd));
    REQUIRE(close(sockets[1]) == 0 && free_delta(&held, 0, 0) == 0);
    char data[4];
    REQUIRE(pread(fd, data, sizeof(data), 0) == sizeof(data) && !memcmp(data, "held", 4));
    REQUIRE(close(fd) == 0 && free_delta(&held, 1, 1) == 0);
    return 0;
}

static int bound_socket(void) {
    static const char path[] = TOP "/bound";
    struct sockaddr_un name = {.sun_family = AF_UNIX};
    REQUIRE(sizeof(path) <= sizeof(name.sun_path));
    memcpy(name.sun_path, path, sizeof(path));
    int server = socket(AF_UNIX, SOCK_DGRAM, 0);
    REQUIRE(server >= 0 && bind(server, (struct sockaddr*)&name, sizeof(name)) == 0);
    REQUIRE(unlink(path) == 0);
    struct statfs held;
    REQUIRE(statfs(TOP, &held) == 0 && close(server) == 0 && free_delta(&held, 1, 0) == 0);
    return 0;
}

static const char helper[] = TOP "/release-child";

static void exec_waiting(int gate, int ready) {
    char readfd[16], signal[16];
    snprintf(readfd, sizeof(readfd), "%d", gate);
    snprintf(signal, sizeof(signal), "%d", ready);
    execl(helper, helper, "held-exec", readfd, signal, (char*)NULL);
    _exit(127);
}

static int exec_releases_mapping(size_t page) {
    static const char path[] = TOP "/exec-map";
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    REQUIRE(fd >= 0 && write(fd, "x", 1) == 1);
    char* map = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fd, 0);
    REQUIRE(map != MAP_FAILED);
    struct statfs held;
    REQUIRE(unlink(path) == 0 && statfs(TOP, &held) == 0 && close(fd) == 0);
    int ready[2], gate[2];
    REQUIRE(pipe(ready) == 0 && pipe(gate) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (!child) {
        char command;
        close(ready[0]);
        close(gate[1]);
        if (read(gate[0], &command, 1) != 1 || *map != 'x')
            _exit(1);
        exec_waiting(gate[0], ready[1]);
    }
    REQUIRE(close(ready[1]) == 0 && close(gate[0]) == 0);
    REQUIRE(munmap(map, page) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(write(gate[1], "x", 1) == 1);
    char observed;
    REQUIRE(read(ready[0], &observed, 1) == 1 && close(ready[0]) == 0 && observed == 'y');
    REQUIRE(free_delta(&held, 1, 1) == 0);
    REQUIRE(write(gate[1], "x", 1) == 1 && close(gate[1]) == 0 && wait_success(child) == 0);
    return 0;
}

static int executable(void) {
    struct stat info;
    struct statfs held;
    int ready[2], gate[2];
    REQUIRE(stat(helper, &info) == 0 && info.st_blocks && pipe(ready) == 0 && pipe(gate) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (!child) {
        close(ready[0]);
        close(gate[1]);
        exec_waiting(gate[0], ready[1]);
    }
    char observed;
    REQUIRE(close(ready[1]) == 0 && close(gate[0]) == 0);
    REQUIRE(read(ready[0], &observed, 1) == 1 && close(ready[0]) == 0 && observed == 'y');
    REQUIRE(statfs(TOP, &held) == 0 && unlink(helper) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(write(gate[1], "x", 1) == 1 && close(gate[1]) == 0 && wait_success(child) == 0);
    REQUIRE(free_delta(&held, 1, info.st_blocks / (held.f_bsize / 512)) == 0);
    return 0;
}

#ifndef NATIVE_TEST
static int held_mapping_cut(void) {
    static const char path[] = TOP "/victim";
    static const char contents[] = "retained through close\n";
    int fd = open(path, O_RDONLY);
    REQUIRE(fd >= 0);
    char* map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    REQUIRE(map != MAP_FAILED);
    struct statfs held;
    REQUIRE(unlink(path) == 0 && statfs(TOP, &held) == 0 && close(fd) == 0);
    REQUIRE(free_delta(&held, 0, 0) == 0 && !memcmp(map, contents, sizeof(contents) - 1));
    puts("EXT2_LAST_REFERENCE_MAPPING_HELD");
    fflush(stdout);
    for (;;)
        pause();
}

static int fault_close(const char* phase) {
    const char* path = TOP "/victim";
    struct statfs held;
    int fd = open(path, O_RDONLY);
    REQUIRE(fd >= 0 && unlink(path) == 0 && statfs(TOP, &held) == 0 && close(fd) == 0);
    if (!strcmp(phase, "pressure")) {
        puts("EXT2_LAST_REFERENCE_FAULT_ARMED");
        fflush(stdout);
        for (;;)
            pause();
    }
    int root = open(TOP, O_RDONLY | O_DIRECTORY);
    REQUIRE(root >= 0 && fsync(root) == 0 && close(root) == 0);
    REQUIRE(free_delta(&held, 1, 1) == 0);
    return 0;
}
#endif

int main(int argc, char** argv) {
    if (argc == 4 && !strcmp(argv[1], "held-exec")) {
        char command;
        REQUIRE(write(atoi(argv[3]), "y", 1) == 1 && read(atoi(argv[2]), &command, 1) == 1);
        return 0;
    }
#ifdef NATIVE_TEST
    const char* phase = "write";
#else
    const char* phase = getenv("AXIOM64_PHASE");
    REQUIRE(phase && mkdir(TOP, 0755) == 0);
    int verify = !strcmp(phase, "verify");
    REQUIRE(mount("/dev/vda", TOP, "ext2", verify ? MS_RDONLY : 0, NULL) == 0);
#endif
    if (!strcmp(phase, "write")) {
        long page = sysconf(_SC_PAGESIZE);
        REQUIRE(page > 0);
        REQUIRE(separate_descriptions() == 0);
        REQUIRE(inherited_description() == 0);
        REQUIRE(directory_pins() == 0);
        REQUIRE(passed_description() == 0);
        REQUIRE(bound_socket() == 0);
        REQUIRE(split_mapping(page) == 0);
        REQUIRE(replace_mapping(page) == 0);
        REQUIRE(exec_releases_mapping(page) == 0);
        REQUIRE(executable() == 0);
    }
#ifndef NATIVE_TEST
    else if (verify) {
        REQUIRE(access(TOP "/victim", F_OK) == -1 && errno == ENOENT);
    } else if (!strcmp(phase, "mapping-held")) {
        REQUIRE(held_mapping_cut() == 0);
    } else {
        REQUIRE(fault_close(phase) == 0);
    }
    REQUIRE(umount(TOP) == 0);
#endif
    puts("EXT2_LAST_REFERENCE_PASS");
    fflush(stdout);
#ifndef NATIVE_TEST
    reboot(RB_POWER_OFF);
    return 1;
#else
    return 0;
#endif
}

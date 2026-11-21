// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext2-last-reference.c
 * @brief   Check reclamation on the last ext-family inode reference.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Exercises final descriptor, task, pathname, executable and Unix socket ownership.
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

static int executable(void) {
    const char* path = TOP "/release-child";
    struct stat info;
    struct statfs held;
    int ready[2], gate[2];
    REQUIRE(stat(path, &info) == 0 && info.st_blocks && pipe(ready) == 0 && pipe(gate) == 0);
    pid_t child = fork();
    REQUIRE(child >= 0);
    if (!child) {
        char readfd[16], signal[16];
        close(ready[0]);
        close(gate[1]);
        snprintf(readfd, sizeof(readfd), "%d", gate[0]);
        snprintf(signal, sizeof(signal), "%d", ready[1]);
        execl(path, path, "held-exec", readfd, signal, (char*)NULL);
        _exit(127);
    }
    char observed;
    REQUIRE(close(ready[1]) == 0 && close(gate[0]) == 0);
    REQUIRE(read(ready[0], &observed, 1) == 1 && close(ready[0]) == 0 && observed == 'y');
    REQUIRE(statfs(TOP, &held) == 0 && unlink(path) == 0 && free_delta(&held, 0, 0) == 0);
    REQUIRE(write(gate[1], "x", 1) == 1 && close(gate[1]) == 0 && wait_success(child) == 0);
    REQUIRE(free_delta(&held, 1, info.st_blocks / (held.f_bsize / 512)) == 0);
    return 0;
}

#ifndef NATIVE_TEST
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
        REQUIRE(separate_descriptions() == 0);
        REQUIRE(inherited_description() == 0);
        REQUIRE(directory_pins() == 0);
        REQUIRE(passed_description() == 0);
        REQUIRE(bound_socket() == 0);
        REQUIRE(executable() == 0);
    }
#ifndef NATIVE_TEST
    else if (verify) {
        REQUIRE(access(TOP "/victim", F_OK) == -1 && errno == ENOENT);
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

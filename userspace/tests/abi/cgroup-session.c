// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/abi/cgroup-session.c
 * @brief   Verify process membership and session population in cgroup v2.
 * @author  frankischilling
 * @date    2026-11-23
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
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "CGROUP_SESSION_FAIL line=%d errno=%d %s\n", __LINE__, errno, #expr);  \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static void read_file(const char* path, char* text, size_t capacity) {
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    ssize_t count = read(fd, text, capacity - 1);
    CHECK(count >= 0 && (size_t)count < capacity - 1);
    text[count] = 0;
    CHECK(read(fd, text + count + 1, 1) == 0);
    CHECK(close(fd) == 0);
}

static void expect_file(const char* path, const char* expected) {
    char text[256];
    read_file(path, text, sizeof(text));
    CHECK(strcmp(text, expected) == 0);
}

static void migrate(const char* path, pid_t pid) {
    char text[32];
    int count = snprintf(text, sizeof(text), "%d\n", pid);
    CHECK(count > 0 && (size_t)count < sizeof(text));
    int fd = open(path, O_WRONLY);
    CHECK(fd >= 0);
    CHECK(write(fd, text, count) == count);
    CHECK(close(fd) == 0);
}

int main(void) {
    CHECK(mount("cgroup2", "/cg", "cgroup2", 0, NULL) == 0);
    struct statfs stats;
    CHECK(statfs("/cg", &stats) == 0 && stats.f_type == 0x63677270);
    char mounts[2048];
    read_file("/proc/mounts", mounts, sizeof(mounts));
    CHECK(strstr(mounts, "cgroup2 /cg cgroup2 rw,nosuid,nodev,noexec 0 0\n"));
    expect_file("/cg/cgroup.controllers", "");
    expect_file("/proc/self/cgroup", "0::/\n");
    CHECK(mkdir("/cg/session", 0755) == 0);
    CHECK(mkdir("/cg/session/child", 0755) == 0);
    expect_file("/cg/session/cgroup.type", "domain\n");
    expect_file("/cg/session/cgroup.events", "populated 0\nfrozen 0\n");

    int events = inotify_init1(IN_NONBLOCK);
    CHECK(events >= 0);
    int watch = inotify_add_watch(events, "/cg/session/cgroup.events", IN_MODIFY);
    CHECK(watch >= 0);
    migrate("/cg/session/child/cgroup.procs", 0);
    expect_file("/proc/self/cgroup", "0::/session/child\n");
    expect_file("/cg/session/cgroup.events", "populated 1\nfrozen 0\n");
    struct inotify_event event;
    CHECK(read(events, &event, sizeof(event)) == sizeof(event));
    CHECK(event.wd == watch && event.mask == IN_MODIFY);
    CHECK(rmdir("/cg/session/child") == -1 && errno == EBUSY);

    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(ready[1]) == 0);
        expect_file("/proc/self/cgroup", "0::/session/child\n");
        CHECK(setgid(65534) == 0 && setuid(65534) == 0);
        CHECK(open("/cg/cgroup.procs", O_WRONLY) == -1 && errno == EACCES);
        char signal;
        CHECK(read(ready[0], &signal, 1) == 0);
        _Exit(0);
    }
    CHECK(close(ready[0]) == 0);
    migrate("/cg/cgroup.procs", getpid());
    expect_file("/proc/self/cgroup", "0::/\n");
    expect_file("/cg/session/cgroup.events", "populated 1\nfrozen 0\n");
    char expected[32];
    CHECK(snprintf(expected, sizeof(expected), "%d\n", child) > 0);
    expect_file("/cg/session/child/cgroup.procs", expected);
    CHECK(read(events, &event, sizeof(event)) == -1 && errno == EAGAIN);
    CHECK(close(ready[1]) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    expect_file("/cg/session/cgroup.events", "populated 0\nfrozen 0\n");
    CHECK(read(events, &event, sizeof(event)) == sizeof(event));
    CHECK(event.wd == watch && event.mask == IN_MODIFY);
    CHECK(close(events) == 0);

    int processes = open("/cg/session/child/cgroup.procs", O_WRONLY);
    CHECK(processes >= 0);
    CHECK(write(processes, "1x\n", 3) == -1 && errno == EINVAL);
    CHECK(rmdir("/cg/session/child") == 0);
    CHECK(write(processes, "0\n", 2) == -1 && errno == ENODEV);
    CHECK(close(processes) == 0);
    CHECK(rmdir("/cg/session") == 0);
    CHECK(umount("/cg") == 0);
    CHECK(mount("cgroup2", "/cg", "cgroup2", MS_RDONLY, NULL) == 0);
    CHECK(mkdir("/cg/rejected", 0755) == -1 && errno == EROFS);
    CHECK(umount("/cg") == 0);
    puts("CGROUP_SESSION_PASS");
    return 0;
}

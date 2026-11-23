// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/abi/tmpfs.c
 * @brief   Verify bounded tmpfs mount and lifetime behavior.
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
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "TMPFS_FAIL line=%d errno=%d %s\n", __LINE__, errno, #expr);           \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static void free_space(unsigned blocks, unsigned inodes) {
    struct statfs stats;
    CHECK(statfs("/ram", &stats) == 0);
    CHECK(stats.f_type == 0x01021994 && stats.f_bsize == 4096);
    CHECK(stats.f_blocks == 2 && stats.f_bfree == blocks && stats.f_bavail == blocks);
    CHECK(stats.f_files == 3 && stats.f_ffree == inodes);
}

int main(void) {
    CHECK(mount("tmpfs", "/ram", "tmpfs", 0, "mode=0788") == -1 && errno == EINVAL);
    CHECK(mount("tmpfs", "/ram", "tmpfs", 0, "size=18446744073709551616") == -1 && errno == EINVAL);
    CHECK(mount("tmpfs", "/ram", "tmpfs", 0, "unknown=1") == -1 && errno == EINVAL);
    CHECK(mount("tmpfs", "/ram", "tmpfs", MS_NOSUID | MS_NODEV,
                "mode=0700,uid=1000,gid=1001,size=8k,nr_inodes=3") == 0);
    struct stat root;
    CHECK(stat("/ram", &root) == 0 && S_ISDIR(root.st_mode));
    CHECK((root.st_mode & 07777) == 0700 && root.st_uid == 1000 && root.st_gid == 1001);
    free_space(2, 2);
    FILE* mounts = fopen("/proc/mounts", "r");
    CHECK(mounts);
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), mounts))
        if (!strcmp(line, "tmpfs /ram tmpfs rw,nosuid,nodev 0 0\n"))
            found = 1;
    CHECK(fclose(mounts) == 0 && found);

    int first = open("/ram/first", O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(first >= 0);
    CHECK(ftruncate(first, 8192) == 0);
    CHECK(write(first, "keep", 4) == 4);
    free_space(0, 1);
    CHECK(ftruncate(first, 8193) == -1 && errno == ENOSPC);
    CHECK(link("/ram/first", "/ram/alias") == 0);
    CHECK(mkdir("/ram/full", 0755) == -1 && errno == ENOSPC);
    CHECK(unlink("/ram/alias") == 0);
    int second = open("/ram/second", O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(second >= 0 && write(second, "!", 1) == -1 && errno == ENOSPC);

    CHECK(ftruncate(first, 4096) == 0);
    free_space(1, 0);
    char text[4];
    CHECK(pread(first, text, sizeof(text), 0) == sizeof(text) && !memcmp(text, "keep", 4));
    CHECK(write(second, "!", 1) == 1);
    CHECK(unlink("/ram/first") == 0);
    free_space(0, 0);
    CHECK(close(first) == 0);
    free_space(1, 1);
    CHECK(umount("/ram") == -1 && errno == EBUSY);
    CHECK(close(second) == 0);

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgid(1002) == 0 && setuid(1002) == 0);
        CHECK(open("/ram/second", O_RDONLY) == -1 && errno == EACCES);
        CHECK(umount("/ram") == -1 && errno == EPERM);
        _Exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(umount("/ram") == 0);
    CHECK(access("/ram/second", F_OK) == -1 && errno == ENOENT);
    CHECK(mount("tmpfs", "/ram", "tmpfs", MS_RDONLY, "nr_blocks=2,nr_inodes=3") == 0);
    CHECK(stat("/ram", &root) == 0 && (root.st_mode & 07777) == 01777);
    free_space(2, 2);
    CHECK(mkdir("/ram/readonly", 0755) == -1 && errno == EROFS);
    CHECK(umount("/ram") == 0);
    puts("TMPFS_PASS");
    return 0;
}

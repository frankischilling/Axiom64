// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext4-orphan.c
 * @brief   Check native ext4 orphan recovery in a running guest.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Checks stored file and namespace state after mounting an interrupted image.
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#define REQUIRE(test)                                                                              \
    do {                                                                                           \
        if (!(test)) {                                                                             \
            printf("EXT4_ORPHAN_FAIL line=%d errno=%d %s\n", __LINE__, errno, #test);              \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static int check_volume(int readonly) {
    struct statfs fs;
    struct stat st;
    REQUIRE(statfs("/mnt", &fs) == 0 && fs.f_type == 0xef53);
    int fd = open("/mnt/shrink", O_RDONLY);
    REQUIRE(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 5000 && st.st_nlink == 1);
    REQUIRE(st.st_blocks ==
            (blkcnt_t)((5000 + fs.f_bsize - 1) / fs.f_bsize) * (blkcnt_t)(fs.f_bsize / 512));
    uint8_t data[5000];
    REQUIRE(read(fd, data, sizeof(data)) == sizeof(data));
    for (unsigned i = 0; i < sizeof(data); i++)
        REQUIRE(data[i] == (i % 251) + 1);
    REQUIRE(read(fd, data, 1) == 0 && close(fd) == 0);
    REQUIRE(access("/mnt/retire", F_OK) == -1 && errno == ENOENT);
    REQUIRE(access("/mnt/retired-dir", F_OK) == -1 && errno == ENOENT);
    fd = open("/mnt/independent", O_RDONLY);
    REQUIRE(fd >= 0 && read(fd, data, sizeof(data)) == 10 && !memcmp(data, "unchanged\n", 10));
    REQUIRE(close(fd) == 0);
    if (readonly)
        REQUIRE(open("/mnt/shrink", O_RDWR) == -1 && errno == EROFS);
    return 0;
}

static int exercise(const char* phase) {
    int root = !strcmp(phase, "io");
    int readonly = strcmp(phase, "write") && !root;
    if (!root) {
        REQUIRE(mkdir("/mnt", 0755) == 0);
        int result = mount("/dev/vda", "/mnt", "ext4", readonly ? MS_RDONLY : 0, NULL);
        if (!strcmp(phase, "invalid") || !strcmp(phase, "error")) {
            REQUIRE(result == -1 && errno == (!strcmp(phase, "invalid") ? EUCLEAN : EROFS));
            puts("EXT4_ORPHAN_REJECT_PASS");
            return 0;
        }
        if (!strcmp(phase, "pressure")) {
            REQUIRE(result == -1 && errno == EIO);
            puts("EXT4_ORPHAN_HOME_WRITE_FAULT");
            fflush(stdout);
            for (;;)
                pause();
        }
        REQUIRE(result == 0);
    }
    REQUIRE(check_volume(readonly) == 0);
    if (!root)
        REQUIRE(umount("/mnt") == 0);
    puts("EXT4_ORPHAN_RECOVERY_PASS");
    return 0;
}

int main(void) {
    const char* phase = getenv("AXIOM64_PHASE");
    int result = phase ? exercise(phase) : 1;
    fflush(stdout);
    if (!result)
        reboot(RB_POWER_OFF);
    return 1;
}

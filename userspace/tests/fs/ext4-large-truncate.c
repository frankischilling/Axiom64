// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext4-large-truncate.c
 * @brief   Check multi-transaction ext4 file shrinking.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Checks data retention, block reclamation, retry and reboot after interruption.
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
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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
            printf("EXT4_TRUNCATE_FAIL line=%d errno=%d %s\n", __LINE__, errno, #test);            \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static const char path[] = "/mnt/shrink";

enum { retained = 5000, enlarged = 18000, original = 275001 * 1024 };

static int check_prefix(int fd) {
    unsigned char data[retained + 1];
    REQUIRE(pread(fd, data, sizeof(data), 0) == retained);
    for (unsigned i = 0; i < retained; i++)
        REQUIRE(data[i] == i % 251 + 1);
    return 0;
}

static int regrow(int fd) {
    REQUIRE(ftruncate(fd, enlarged) == 0);
    unsigned char data[enlarged - retained];
    REQUIRE(pread(fd, data, sizeof(data), retained) == sizeof(data));
    for (unsigned i = 0; i < sizeof(data); i++)
        REQUIRE(data[i] == 0);
    REQUIRE(ftruncate(fd, retained) == 0 && check_prefix(fd) == 0);
    return 0;
}

static int exercise(const char* phase) {
    int verify = !strcmp(phase, "verify"), cut = !strcmp(phase, "pressure");
    int retry = !strcmp(phase, "recovery"), unlinked = !strcmp(phase, "cond");
    int open_trunc = !strcmp(phase, "cache"), by_path = !strcmp(phase, "io");
    REQUIRE(mkdir("/mnt", 0755) == 0);
    REQUIRE(mount("/dev/vda", "/mnt", "ext4", verify ? MS_RDONLY : 0, NULL) == 0);
    int fd = open(path, verify ? O_RDONLY : O_RDWR);
    struct stat before, after;
    REQUIRE(fd >= 0 && fstat(fd, &before) == 0);
    if (verify) {
        REQUIRE(before.st_nlink == 1 && before.st_size == retained && before.st_blocks == 10);
        REQUIRE(check_prefix(fd) == 0);
    } else {
        struct statfs space_before, space_after;
        REQUIRE(before.st_size == original && before.st_blocks > 550000);
        REQUIRE(statfs("/mnt", &space_before) == 0 && space_before.f_bsize == 1024);
        if (unlinked)
            REQUIRE(unlink(path) == 0);
        if (open_trunc) {
            REQUIRE(close(fd) == 0);
            fd = open(path, O_RDWR | O_TRUNC);
            REQUIRE(fd >= 0);
        } else {
            int result = by_path ? truncate(path, retained) : ftruncate(fd, retained);
            if (cut || retry)
                REQUIRE(result == -1 && errno == EIO);
            else
                REQUIRE(result == 0);
        }
        REQUIRE(fstat(fd, &after) == 0 && after.st_ino == before.st_ino);
        REQUIRE(after.st_size == (open_trunc ? 0 : retained));
        REQUIRE(after.st_nlink == !unlinked);
        if (!open_trunc)
            REQUIRE(check_prefix(fd) == 0);
        if (cut) {
            puts("EXT4_TRUNCATE_HOME_FAULT");
            fflush(stdout);
            for (;;)
                pause();
        }
        if (retry) {
            // Growing immediately must finish releasing the old mapping first.
            REQUIRE(regrow(fd) == 0 && fstat(fd, &after) == 0);
        }
        REQUIRE(after.st_blocks == (open_trunc ? 0 : 10));
        REQUIRE(statfs("/mnt", &space_after) == 0);
        REQUIRE(space_after.f_bfree - space_before.f_bfree ==
                (fsblkcnt_t)(before.st_blocks - after.st_blocks) / 2);
        REQUIRE(space_after.f_ffree == space_before.f_ffree);
        if (!retry && !open_trunc)
            REQUIRE(regrow(fd) == 0);
    }
    REQUIRE(close(fd) == 0 && umount("/mnt") == 0);
    puts("EXT4_TRUNCATE_PASS");
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

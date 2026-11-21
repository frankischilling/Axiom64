// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext2-journal.c
 * @brief   Ext2 journal workload.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Performs filesystem updates used to verify journal publication and replay.
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
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "EXT2_JOURNAL_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno, \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void all(int fd, const unsigned char* data, size_t length) {
    size_t done = 0;
    while (done < length) {
        ssize_t count = write(fd, data + done, length - done);
        CHECK(count > 0);
        done += (size_t)count;
    }
}

static void exercise(const char* mode) {
    CHECK(!getuid() && !geteuid());
    CHECK(mkdir("/mnt", 0755) == 0 || errno == EEXIST);
    CHECK(mkdir("/mnt/journal", 0755) == 0);
    int verify = !strcmp(mode, "verify"), cut_replay = !strcmp(mode, "readonly");
    int discard = !strcmp(mode, "recovery"), fault = !strcmp(mode, "error");
    int readonly = verify || cut_replay;
    int mounted = mount("/dev/vda", "/mnt/journal", "ext2", readonly ? MS_RDONLY : 0, NULL);
    if (!strcmp(mode, "invalid")) {
        CHECK(mounted == -1 && errno == EUCLEAN);
        puts("EXT2_JOURNAL_CHECKSUM_REJECT_PASS");
        return;
    }
    CHECK(mounted == 0);
    struct statfs filesystem;
    CHECK(statfs("/mnt/journal", &filesystem) == 0 && filesystem.f_type == 0xef53 &&
          (filesystem.f_bsize == 1024 || filesystem.f_bsize == 2048 || filesystem.f_bsize == 4096));
    size_t size = (size_t)filesystem.f_bsize;
    size_t historical = 9 * size - 128, length = historical + (discard ? 0 : 448);
    size_t extra = 2 * size + 37, expected = length + (readonly ? extra : 0);
    int fd = open("/mnt/journal/seed", (readonly ? O_RDONLY : O_RDWR) | O_CLOEXEC);
    struct stat value;
    CHECK(fd >= 0 && fstat(fd, &value) == 0 && value.st_size == (off_t)expected &&
          S_ISREG(value.st_mode) && value.st_uid == 0 && value.st_gid == 0 && value.st_nlink == 1);
    unsigned char* data = malloc(length + extra);
    CHECK(data != NULL);
    size_t done = 0;
    while (done < expected) {
        ssize_t count = read(fd, data + done, expected - done);
        CHECK(count > 0);
        done += (size_t)count;
    }
    for (size_t index = 0; index < historical; index++)
        CHECK(data[index] == (unsigned char)(index * 31 + 17));
    for (size_t index = 0; index < length - historical; index++)
        CHECK(data[historical + index] == (unsigned char)(index * 13 + 9));
    if (!strcmp(mode, "write") || fault) {
        for (size_t index = 0; index < extra; index++)
            data[length + index] = (unsigned char)(index * 7 + 3);
        if (fault) {
            CHECK(write(fd, data + length, extra) == -1 && errno == EIO);
            puts("EXT2_JOURNAL_HOME_WRITE_FAULT");
            fflush(stdout);
            for (;;)
                pause();
        }
        all(fd, data + length, extra);
        CHECK(fsync(fd) == 0);
        CHECK(mkdir("/mnt/journal/work", 0700) == 0);
        int created = open("/mnt/journal/work/new", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        CHECK(created >= 0);
        all(created, data, size + 97);
        CHECK(fsync(created) == 0 && close(created) == 0);
        CHECK(rename("/mnt/journal/work/new", "/mnt/journal/work/final") == 0);
        int parent = open("/mnt/journal/work", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(parent >= 0 && fsync(parent) == 0 && close(parent) == 0);
    } else if (readonly) {
        for (size_t index = 0; index < extra; index++)
            CHECK(data[length + index] == (unsigned char)(index * 7 + 3));
        if (verify) {
            int created = open("/mnt/journal/work/final", O_RDONLY | O_CLOEXEC);
            CHECK(created >= 0);
            unsigned char* copy = malloc(size + 97);
            CHECK(copy && read(created, copy, size + 97) == (ssize_t)(size + 97));
            CHECK(!memcmp(copy, data, size + 97) && close(created) == 0);
            free(copy);
        }
    } else {
        CHECK(discard || !strcmp(mode, "read"));
    }
    CHECK(close(fd) == 0);
    free(data);
    CHECK(umount("/mnt/journal") == 0);
    printf("EXT2_JOURNAL_PASS mode=%s block_size=%zu historical_bytes=%zu\n", mode, size,
           historical);
}

int main(int argc, char** argv) {
    const char* mode = argc == 2 ? argv[1] : argc == 1 ? getenv("AXIOM64_PHASE") : NULL;
    CHECK(mode);
    exercise(mode);
    if (argc == 1) {
        fflush(stdout);
        reboot(RB_POWER_OFF);
        return 1;
    }
    return 0;
}

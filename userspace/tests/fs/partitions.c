// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/partitions.c
 * @brief   Guest partition I/O and mount regression.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Checks partition geometry, overlapping claims, disjoint mounts and reboot persistence.
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
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define CHECK(test)                                                                                \
    do {                                                                                           \
        if (!(test)) {                                                                             \
            fprintf(stderr, "PARTITIONS_FAIL line=%d errno=%d: %s\n", __LINE__, errno, #test);     \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static const char payload[] = "Axiom64 partition persistence\n";

static void persisted(const char* path, int verify) {
    int fd = open(path, verify ? O_RDONLY : O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0);
    if (verify) {
        char buffer[sizeof(payload)];
        CHECK(read(fd, buffer, sizeof(buffer)) == sizeof(buffer));
        CHECK(!memcmp(buffer, payload, sizeof(payload)));
        CHECK(read(fd, buffer, 1) == 0);
    } else {
        CHECK(write(fd, payload, sizeof(payload)) == sizeof(payload));
        CHECK(fsync(fd) == 0);
    }
    CHECK(close(fd) == 0);
}

int main(void) {
    char disk[12], root[12], sibling[12], raw[12], parent[12];
    unsigned expected_major, expected_minor;
    FILE* layout = fopen("/layout", "r");
    CHECK(layout);
    CHECK(fscanf(layout, "%11s %11s %11s %11s %11s %u %u", disk, root, sibling, raw, parent,
                 &expected_major, &expected_minor) == 7);
    CHECK(fclose(layout) == 0);

    CHECK(open(disk, O_WRONLY) == -1 && errno == EBUSY);
    CHECK(open(root, O_WRONLY) == -1 && errno == EBUSY);
    if (strcmp(parent, "-"))
        CHECK(open(parent, O_WRONLY) == -1 && errno == EBUSY);
    int diskfd = open(disk, O_RDONLY);
    int siblingfd = open(sibling, O_RDWR);
    int rawfd = open(raw, O_RDWR);
    CHECK(diskfd >= 0 && siblingfd >= 0 && rawfd >= 0);
    struct stat info;
    CHECK(fstat(siblingfd, &info) == 0 && S_ISBLK(info.st_mode));
    CHECK(major(info.st_rdev) == expected_major && minor(info.st_rdev) == expected_minor);
    uint64_t bytes;
    int size;
    CHECK(ioctl(siblingfd, 0x80081272, &bytes) == 0 && bytes == 16 * 1024 * 1024);
    CHECK(ioctl(rawfd, 0x1268, &size) == 0 && size == 512);
    off_t end = lseek(rawfd, 0, SEEK_END);
    CHECK(end == 1000 * 512);
    char buffer[512] = {0};
    CHECK(pread(rawfd, buffer, 1, end) == 0);
    CHECK(pread(rawfd, buffer, 1, end - 1) == 1);

    int verify = access("/persisted", F_OK) == 0;
    CHECK(verify ? buffer[0] == 'p' : buffer[0] == 0);
    if (!verify) {
        CHECK(pwrite(rawfd, "pq", 2, end - 1) == 1);
        CHECK(pwrite(rawfd, "q", 1, end) == -1 && errno == ENOSPC);
        CHECK(fsync(rawfd) == 0);
    }
    CHECK(mount(sibling, "/mnt", "ext2", 0, NULL) == 0);
    CHECK(pwrite(siblingfd, buffer, sizeof(buffer), 0) == -1 && errno == EBUSY);
    CHECK(mount(sibling, "/other", "ext2", 0, NULL) == -1 && errno == EBUSY);
    persisted("/persisted", verify);
    persisted("/mnt/persisted", verify);
    CHECK(umount("/mnt") == 0);
    int reopened = open(sibling, O_WRONLY);
    CHECK(reopened >= 0 && close(reopened) == 0);
    CHECK(close(rawfd) == 0 && close(siblingfd) == 0 && close(diskfd) == 0);
    puts(verify ? "PARTITIONS_REBOOT_PASS" : "PARTITIONS_WRITE_PASS");
    CHECK(fflush(stdout) == 0);
    CHECK(reboot(RB_POWER_OFF) == 0);
    return 1;
}

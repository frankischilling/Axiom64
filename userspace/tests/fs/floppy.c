// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/floppy.c
 * @brief   Check floppy nodes and filesystem persistence.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Exercises both drives, write protection, block limits, and a writable ext2 mount.
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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define DISK_SIZE_IOCTL _IOR(0x12, 114, size_t)
#define DISK_READONLY_IOCTL _IO(0x12, 94)

enum { sector = 512, media_size = 2880 * sector };

static const char payload[] = "FD persistence\n";

static int missing(const char* path) {
    struct stat st;
    return stat(path, &st) < 0 && errno == ENOENT;
}

static int describe(const char* path, unsigned minor_id, int readonly) {
    int fd = open(path, readonly ? O_RDONLY : O_RDWR);
    struct stat st;
    uint64_t size;
    int ro;
    if (fd < 0 || fstat(fd, &st) || !S_ISBLK(st.st_mode) || major(st.st_rdev) != 2 ||
        minor(st.st_rdev) != minor_id || ioctl(fd, DISK_SIZE_IOCTL, &size) || size != media_size ||
        ioctl(fd, DISK_READONLY_IOCTL, &ro) || ro != readonly)
        return -1;
    return fd;
}

static int check_raw(void) {
    int zero = describe("/dev/fd0", 0, 0);
    int one = describe("/dev/fd1", 1, 1);
    char buffer[sizeof(payload)];
    if (zero < 0 || one < 0 || open("/dev/fd1", O_RDWR) != -1 || errno != EROFS)
        return -1;
    if (pread(one, buffer, 8, 0) != 8 || memcmp(buffer, "READONLY", 8))
        return -1;
    // Split a partial transfer over a track boundary and leave both adjacent bytes intact.
    off_t boundary = 36 * sector;
    if (pwrite(zero, payload, sizeof(payload), boundary - 4) != sizeof(payload) || fsync(zero) ||
        pread(zero, buffer, sizeof(buffer), boundary - 4) != sizeof(buffer) ||
        memcmp(buffer, payload, sizeof(payload)))
        return -1;
    if (pread(zero, buffer, 8, media_size - 8) != 8 || memcmp(buffer, "LASTSECT", 8) ||
        pread(zero, buffer, 1, media_size) != 0 || pwrite(zero, payload, 1, media_size) != -1 ||
        errno != ENOSPC || close(one) || close(zero))
        return -1;
    return 0;
}

static int check_filesystem(int readback) {
    if (mount("/dev/fd0", "/data", "ext2", 0, NULL))
        return -1;
    int fd = open("/data/persist", readback ? O_RDONLY : O_CREAT | O_EXCL | O_WRONLY, 0600);
    char buffer[sizeof(payload)];
    if (fd < 0)
        return -1;
    if (readback) {
        if (read(fd, buffer, sizeof(buffer)) != sizeof(buffer) ||
            memcmp(payload, buffer, sizeof(buffer)))
            return -1;
    } else if (write(fd, payload, sizeof(payload)) != sizeof(payload) || fsync(fd))
        return -1;
    return close(fd) || umount("/data");
}

static int check_failed_write(void) {
    int fd = describe("/dev/fd0", 0, 0);
    if (fd < 0 || pwrite(fd, payload, sizeof(payload), 120 * sector) != -1 || errno != EIO)
        return -1;
    return pwrite(fd, payload, sizeof(payload), 121 * sector) != sizeof(payload) || fsync(fd) ||
                   close(fd)
               ? -1
               : 0;
}

static int check_media_change(void) {
    int fd = describe("/dev/fd0", 0, 0);
    char bytes[8];
    if (fd < 0 || pread(fd, bytes, sizeof(bytes), 0) != sizeof(bytes) ||
        memcmp(bytes, "ORIGINAL", sizeof(bytes)))
        return -1;
    puts("FLOPPY_CHANGE_READY");
    fflush(stdout);
    char reply[2];
    if (read(STDIN_FILENO, reply, sizeof(reply)) != sizeof(reply) || memcmp(reply, "y\n", 2) ||
        pread(fd, bytes, sizeof(bytes), 0) != -1 || errno != EIO ||
        pwrite(fd, payload, sizeof(payload), 0) != -1 || errno != EIO || close(fd))
        return -1;
    return 0;
}

int main(void) {
    char phase;
    int fd = open("/phase", O_RDONLY);
    if (fd < 0 || read(fd, &phase, 1) != 1 || close(fd))
        return 1;
    int status;
    switch (phase) {
    case 'N':
        status = !(missing("/dev/fd0") && missing("/dev/fd1"));
        break;
    case 'D':
        status = check_raw();
        break;
    case 'F':
        status = check_failed_write();
        break;
    case 'M':
        status = check_media_change();
        break;
    case 'W':
    case 'R':
        status = check_filesystem(phase == 'R');
        break;
    default:
        return 1;
    }
    if (status) {
        fprintf(stderr, "FLOPPY_CHECK_FAIL phase=%c errno=%d\n", phase, errno);
        return 1;
    }
    printf("FLOPPY_CHECK_PASS phase=%c\n", phase);
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}

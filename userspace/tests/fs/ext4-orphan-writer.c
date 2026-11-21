// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext4-orphan-writer.c
 * @brief   Exercise native orphan records in a running guest.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Exercising a guest unlink, replacement, close and shutdown leaves native orphan evidence.
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
#include <dirent.h>
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

static int verify_replacement(int fault) {
    REQUIRE(access("/mnt/kept", F_OK) == -1 && errno == ENOENT);
    REQUIRE(access("/mnt/open-dir", F_OK) == -1 && errno == ENOENT);
    if (fault) {
        REQUIRE(access("/mnt/victim", F_OK) == -1 && errno == ENOENT);
        return 0;
    }
    REQUIRE(access("/mnt/replacement", F_OK) == -1 && errno == ENOENT);
    int fd = open("/mnt/victim", O_RDONLY);
    char data[32];
    static const char replacement[] = "replacement\n";
    REQUIRE(fd >= 0 && read(fd, data, sizeof(data)) == sizeof(replacement) - 1);
    REQUIRE(!memcmp(data, replacement, sizeof(replacement) - 1) && close(fd) == 0);
    return 0;
}

static int hold_slots(unsigned first, unsigned count, int ready) {
    for (unsigned i = first; i < first + count; i++) {
        char name[32];
        REQUIRE(snprintf(name, sizeof(name), "/mnt/slot-%u", i) > 0);
        int fd = open(name, O_CREAT | O_EXCL | O_RDWR, 0600);
        REQUIRE(fd >= 0 && write(fd, "slot", 4) == 4 && unlink(name) == 0);
    }
    REQUIRE(write(ready, "y", 1) == 1);
    for (;;)
        pause();
}

static int fill_orphan_file(void) {
    struct statfs fs;
    REQUIRE(statfs("/mnt", &fs) == 0 && fs.f_bsize == 1024);
    unsigned entries = (fs.f_bsize - 8) / 4;
    for (unsigned first = 0; first < entries; first += 100) {
        int ready[2];
        REQUIRE(pipe(ready) == 0);
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (!child) {
            close(ready[0]);
            _exit(hold_slots(first, entries - first < 100 ? entries - first : 100, ready[1]));
        }
        char marker;
        REQUIRE(close(ready[1]) == 0 && read(ready[0], &marker, 1) == 1 && marker == 'y' &&
                close(ready[0]) == 0);
    }
    return 0;
}

static int reclaim_large(const char* phase) {
    int held = !strcmp(phase, "queue"), replace = !strcmp(phase, "cond");
    if (replace) {
        int replacement = open("/mnt/new", O_WRONLY | O_CREAT | O_EXCL, 0600);
        REQUIRE(replacement >= 0 && write(replacement, "new", 3) == 3 && close(replacement) == 0);
    }
    struct statfs before, after;
    REQUIRE(statfs("/mnt", &before) == 0);
    int fd = held ? open("/mnt/shrink", O_RDONLY) : -1;
    REQUIRE(!held || fd >= 0);
    if (replace) {
        REQUIRE(rename("/mnt/new", "/mnt/shrink") == 0);
        REQUIRE(access("/mnt/new", F_OK) == -1 && errno == ENOENT);
    } else {
        REQUIRE(unlink("/mnt/shrink") == 0);
        REQUIRE(access("/mnt/shrink", F_OK) == -1 && errno == ENOENT);
    }
    if (!strcmp(phase, "invalid")) {
        puts("EXT4_ORPHAN_WRITER_LARGE_ARMED");
        fflush(stdout);
        for (;;)
            pause();
    }
    if (held) {
        char content[2];
        REQUIRE(pread(fd, content, sizeof(content), 0) == sizeof(content) && content[0] == 1 &&
                content[1] == 2);
        REQUIRE(close(fd) == 0);
        int mountpoint = open("/mnt", O_RDONLY);
        REQUIRE(mountpoint >= 0 && fsync(mountpoint) == 0 && close(mountpoint) == 0);
    }
    REQUIRE(statfs("/mnt", &after) == 0);
    REQUIRE(after.f_ffree == before.f_ffree + 1 && after.f_bfree > before.f_bfree + 275000);
    REQUIRE(umount("/mnt") == 0);
    puts("EXT4_ORPHAN_WRITER_PASS");
    return 0;
}

static int writer(const char* phase) {
    int large_verify = !strcmp(phase, "error");
    int verification = !strcmp(phase, "verify") || !strcmp(phase, "readonly") || large_verify;
    REQUIRE(mkdir("/mnt", 0755) == 0);
    REQUIRE(mount("/dev/vda", "/mnt", "ext4", verification ? MS_RDONLY : 0, NULL) == 0);
    if (!strcmp(phase, "cache") || !strcmp(phase, "queue") || !strcmp(phase, "cond") ||
        !strcmp(phase, "invalid"))
        return reclaim_large(phase);
    if (verification) {
        if (large_verify)
            REQUIRE(access("/mnt/shrink", F_OK) == -1 && errno == ENOENT);
        else
            REQUIRE(verify_replacement(!strcmp(phase, "readonly")) == 0);
        REQUIRE(umount("/mnt") == 0);
        puts("EXT4_ORPHAN_WRITER_PASS");
        return 0;
    }
    if (!strcmp(phase, "pressure")) {
        int fd = open("/mnt/victim", O_RDWR);
        REQUIRE(fd >= 0 && unlink("/mnt/victim") == -1 && errno == EIO);
        puts("EXT4_ORPHAN_WRITER_HOME_FAULT");
        fflush(stdout);
        for (;;)
            pause();
    }
    if (!strcmp(phase, "full"))
        REQUIRE(fill_orphan_file() == 0);
    int left = open("/mnt/kept", O_RDWR | O_CREAT | O_EXCL, 0600);
    struct stat first, middle, last;
    REQUIRE(left >= 0 && write(left, "first", 5) == 5);
    REQUIRE(link("/mnt/kept", "/mnt/alias") == 0 && unlink("/mnt/alias") == 0);
    REQUIRE(fstat(left, &first) == 0 && first.st_nlink == 1);
    REQUIRE(unlink("/mnt/kept") == 0 && fstat(left, &first) == 0 && first.st_nlink == 0);
    int replaced = open("/mnt/victim", O_RDWR);
    REQUIRE(replaced >= 0 && rename("/mnt/replacement", "/mnt/victim") == 0);
    char data[16];
    REQUIRE(pread(replaced, data, sizeof(data), 0) == 7 && !memcmp(data, "victim\n", 7));
    REQUIRE(pwrite(replaced, "old", 3, 0) == 3 && fstat(replaced, &middle) == 0 &&
            middle.st_nlink == 0);
    REQUIRE(mkdir("/mnt/open-dir", 0700) == 0);
    int directory = open("/mnt/open-dir", O_RDONLY | O_DIRECTORY);
    REQUIRE(directory >= 0 && rmdir("/mnt/open-dir") == 0);
    REQUIRE(fstat(directory, &last) == 0 && last.st_nlink == 0 && last.st_size == 0);
    REQUIRE(umount("/mnt") == -1 && errno == EBUSY);
    REQUIRE(mount(NULL, "/mnt", NULL, MS_REMOUNT | MS_RDONLY, NULL) == -1 && errno == EBUSY);
    REQUIRE(verify_replacement(0) == 0);
    struct statfs before, after;
    REQUIRE(statfs("/mnt", &before) == 0 && close(replaced) == 0 && fsync(left) == 0 &&
            statfs("/mnt", &after) == 0);
    REQUIRE(after.f_ffree == before.f_ffree + 1 && after.f_bfree == before.f_bfree + 1);
    REQUIRE(pread(left, data, sizeof(data), 0) == 5 && !memcmp(data, "first", 5));
    printf("EXT4_ORPHAN_WRITER_INODES %llu %llu %llu\n", (unsigned long long)first.st_ino,
           (unsigned long long)middle.st_ino, (unsigned long long)last.st_ino);
    if (!strcmp(phase, "write") || !strcmp(phase, "full")) {
        puts("EXT4_ORPHAN_WRITER_ARMED");
        fflush(stdout);
        for (;;)
            pause();
    }
    if (!strcmp(phase, "io")) {
        REQUIRE(close(left) == 0 && close(directory) == 0);
        int mountpoint = open("/mnt", O_RDONLY);
        REQUIRE(mountpoint >= 0 && fsync(mountpoint) == 0 && close(mountpoint) == 0);
        REQUIRE(mount(NULL, "/mnt", NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0);
        REQUIRE(umount("/mnt") == 0);
    }
    puts("EXT4_ORPHAN_WRITER_PASS");
    return 0;
}

int main(void) {
    const char* phase = getenv("AXIOM64_PHASE");
    int result = phase ? writer(phase) : 1;
    fflush(stdout);
    if (!result)
        reboot(RB_POWER_OFF);
    return 1;
}

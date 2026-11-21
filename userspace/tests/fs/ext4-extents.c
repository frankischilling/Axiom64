// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext4-extents.c
 * @brief   Exercise extent-backed files and directories in an Axiom64 guest.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Checks allocated, sparse, and unwritten ranges before and after reboot.
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
#include <sys/wait.h>
#include <unistd.h>

#define REQUIRE(test)                                                                              \
    do {                                                                                           \
        if (!(test)) {                                                                             \
            printf("EXT4_EXTENT_FAIL line=%d errno=%d %s\n", __LINE__, errno, #test);              \
            fflush(stdout);                                                                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

enum { native_count = 96, sparse_count = 400, max_block = 4096 };

static int bytes_are(int fd, off_t offset, size_t size, unsigned char expected) {
    unsigned char data[max_block];
    if (size > sizeof(data) || pread(fd, data, size, offset) != (ssize_t)size)
        return 0;
    for (size_t i = 0; i < size; i++)
        if (data[i] != expected)
            return 0;
    return 1;
}

static int imported(unsigned block, int verify) {
    int fd = open("/mnt/native", verify ? O_RDONLY : O_RDWR);
    REQUIRE(fd >= 0);
    if (!verify) {
        REQUIRE(bytes_are(fd, 0, block, 0));
        REQUIRE(pwrite(fd, "a", 1, 0) == 1);
        REQUIRE(pwrite(fd, "b", 1, 3 * block + 5) == 1);
    }
    REQUIRE(bytes_are(fd, 0, 1, 'a'));
    REQUIRE(bytes_are(fd, 3 * block + 5, 1, 'b'));
    for (unsigned i = 0; i < native_count; i++) {
        REQUIRE(bytes_are(fd, (2 + i * 2) * block, block, 'A' + i % 26));
        if (i && i + 1 < native_count)
            REQUIRE(bytes_are(fd, (3 + i * 2) * block, block, 0));
    }
    REQUIRE(close(fd) == 0);
    return 0;
}

static int unwritten(unsigned block, int verify) {
    int fd = open("/mnt/preallocated", verify ? O_RDONLY : O_RDWR);
    REQUIRE(fd >= 0);
    struct stat st;
    if (!verify) {
        REQUIRE(fstat(fd, &st) == 0 && st.st_size == 14 * block &&
                st.st_blocks == 16 * block / 512);
        REQUIRE(bytes_are(fd, 9 * block, block, 0));
        REQUIRE(ftruncate(fd, 14 * block) == 0);
        REQUIRE(fstat(fd, &st) == 0 && st.st_blocks == 10 * block / 512);
        REQUIRE(pwrite(fd, "UV", 2, 9 * block + 127) == 2);
        REQUIRE(ftruncate(fd, 11 * block) == 0);
        REQUIRE(unlink("/mnt/empty-reserved") == 0);
    }
    REQUIRE(fstat(fd, &st) == 0 && st.st_size == 11 * block && st.st_blocks == 7 * block / 512);
    REQUIRE(bytes_are(fd, 4 * block, block, 0));
    REQUIRE(bytes_are(fd, 9 * block, 127, 0));
    REQUIRE(bytes_are(fd, 9 * block + 127, 1, 'U'));
    REQUIRE(bytes_are(fd, 9 * block + 128, 1, 'V'));
    REQUIRE(bytes_are(fd, 9 * block + 129, block - 129, 0));
    REQUIRE(bytes_are(fd, 10 * block, block, 0));
    REQUIRE(close(fd) == 0);
    REQUIRE(access("/mnt/empty-reserved", F_OK) == -1 && errno == ENOENT);
    return 0;
}

static int fragmented(unsigned block, int verify) {
    const char* path = verify ? "/mnt/renamed/sparse" : "/mnt/generated/sparse";
    int fd = open(path, verify ? O_RDONLY : O_CREAT | O_EXCL | O_RDWR, 0644);
    REQUIRE(fd >= 0);
    for (unsigned i = 0; i < sparse_count; i++) {
        off_t offset = 2 * i * block + 7;
        unsigned char marker = 'a' + i % 26;
        if (!verify)
            REQUIRE(pwrite(fd, &marker, 1, offset) == 1);
        REQUIRE(bytes_are(fd, offset - 7, 7, 0));
        REQUIRE(bytes_are(fd, offset, 1, marker));
        if (verify && i + 1 < sparse_count)
            REQUIRE(bytes_are(fd, offset + block, 1, 0));
    }
    struct stat st, alias;
    REQUIRE(fstat(fd, &st) == 0 && st.st_size == (sparse_count - 1) * 2 * block + 8 &&
            st.st_blocks > sparse_count * block / 512);
    if (!verify)
        REQUIRE(link(path, "/mnt/generated/alias") == 0);
    REQUIRE(stat(verify ? "/mnt/renamed/alias" : "/mnt/generated/alias", &alias) == 0 &&
            alias.st_ino == st.st_ino && alias.st_nlink == 2);
    REQUIRE(close(fd) == 0);
    return 0;
}

static int truncate_tree(unsigned block, int verify) {
    int fd = open("/mnt/trimmed", verify ? O_RDONLY : O_CREAT | O_EXCL | O_RDWR, 0644);
    REQUIRE(fd >= 0);
    if (!verify) {
        char data[max_block];
        memset(data, 'T', block);
        REQUIRE(pwrite(fd, data, block, 0) == (ssize_t)block);
        REQUIRE(pwrite(fd, data, block, block) == (ssize_t)block);
        for (unsigned i = 0; i < sparse_count; i++)
            REQUIRE(pwrite(fd, "x", 1, (4 + 2 * i) * block) == 1);
        REQUIRE(ftruncate(fd, block + 73) == 0 && ftruncate(fd, 4 * block) == 0);
    }
    struct stat st;
    REQUIRE(fstat(fd, &st) == 0 && st.st_size == 4 * block && st.st_blocks == 2 * block / 512);
    REQUIRE(bytes_are(fd, 0, block, 'T'));
    REQUIRE(bytes_are(fd, block, 73, 'T'));
    REQUIRE(bytes_are(fd, block + 73, block - 73, 0));
    REQUIRE(bytes_are(fd, 3 * block, block, 0));
    REQUIRE(close(fd) == 0);
    return 0;
}

static int wide_file(unsigned block, int verify) {
    int fd = open("/mnt/wide", verify ? O_RDONLY : O_CREAT | O_EXCL | O_RDWR, 0644);
    REQUIRE(fd >= 0);
    off_t end = (uint64_t)UINT32_MAX * block;
    if (!verify) {
        REQUIRE(pwrite(fd, "W", 1, end - 1) == 1);
        REQUIRE(pwrite(fd, "X", 1, end) == -1 && errno == EFBIG);
    }
    struct stat st;
    REQUIRE(fstat(fd, &st) == 0 && st.st_size == end && st.st_blocks == block / 512);
    REQUIRE(bytes_are(fd, end - block - 1, block, 0));
    REQUIRE(bytes_are(fd, end - 1, 1, 'W'));
    REQUIRE(close(fd) == 0);
    return 0;
}

static int drop_open_file(unsigned block) {
    int fd = open("/mnt/held", O_CREAT | O_EXCL | O_RDWR, 0644);
    REQUIRE(fd >= 0);
    for (unsigned i = 0; i < 12; i++)
        REQUIRE(pwrite(fd, "H", 1, 2 * i * block) == 1);
    REQUIRE(unlink("/mnt/held") == 0);
    REQUIRE(bytes_are(fd, 22 * block, 1, 'H'));
    REQUIRE(close(fd) == 0);
    return 0;
}

static int full_volume(void) {
    struct statfs before, after;
    REQUIRE(statfs("/mnt", &before) == 0 && before.f_bsize == 1024 && before.f_bfree == 1);
    int fd = open("/mnt/split", O_RDWR);
    REQUIRE(fd >= 0);
    struct stat st;
    REQUIRE(fstat(fd, &st) == 0 && st.st_size == 7 * 1024 && st.st_blocks == 8);
    REQUIRE(pwrite(fd, "x", 1, 8 * 1024) == -1 && errno == ENOSPC);
    REQUIRE(fstat(fd, &st) == 0 && st.st_size == 7 * 1024 && st.st_blocks == 8);
    REQUIRE(statfs("/mnt", &after) == 0 && after.f_bfree == before.f_bfree);
    for (unsigned i = 0; i < 4; i++)
        REQUIRE(bytes_are(fd, 2 * i * 1024, 1024, 'a' + i));
    REQUIRE(close(fd) == 0);
    fd = open("/mnt/last-block", O_CREAT | O_EXCL | O_RDWR, 0644);
    REQUIRE(fd >= 0 && pwrite(fd, "z", 1, 0) == 1);
    REQUIRE(pwrite(fd, "x", 1, 1024) == -1 && errno == ENOSPC);
    REQUIRE(bytes_are(fd, 0, 1, 'z') && close(fd) == 0);
    REQUIRE(statfs("/mnt", &after) == 0 && after.f_bfree == 0);
    REQUIRE(umount("/mnt") == 0);
    puts("EXT4_EXTENT_FULL_PASS");
    return 0;
}

static int exercise(const char* phase) {
    int verify = !strcmp(phase, "verify"), root = !strcmp(phase, "io");
    if (!root) {
        REQUIRE(mkdir("/mnt", 0755) == 0);
        int rc = mount("/dev/vda", "/mnt", "ext4", verify ? MS_RDONLY : 0, NULL);
        if (!strcmp(phase, "invalid") || !strcmp(phase, "error")) {
            REQUIRE(rc == -1 && errno == (!strcmp(phase, "invalid") ? EUCLEAN : EOPNOTSUPP));
            puts("EXT4_EXTENT_REJECTION_PASS");
            return 0;
        }
        REQUIRE(rc == 0);
        if (!strcmp(phase, "full"))
            return full_volume();
    } else {
        pid_t pid = fork();
        REQUIRE(pid >= 0);
        if (!pid) {
            execl("/bin/busybox", "busybox", "true", (char*)NULL);
            _exit(127);
        }
        int status;
        REQUIRE(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    struct statfs filesystem;
    REQUIRE(statfs("/mnt", &filesystem) == 0 && filesystem.f_type == 0xef53);
    unsigned block = filesystem.f_bsize;
    REQUIRE(block == 1024 || block == 2048 || block == 4096);
    if (!verify)
        REQUIRE(mkdir("/mnt/generated", 0755) == 0);
    REQUIRE(imported(block, verify) == 0);
    REQUIRE(unwritten(block, verify) == 0);
    REQUIRE(fragmented(block, verify) == 0);
    REQUIRE(truncate_tree(block, verify) == 0);
    REQUIRE(wide_file(block, verify) == 0);
    if (!verify) {
        REQUIRE(drop_open_file(block) == 0);
        REQUIRE(rename("/mnt/generated", "/mnt/renamed") == 0);
    }
    char target[136], readback[136];
    memset(target, 'L', sizeof(target) - 1);
    target[sizeof(target) - 1] = 0;
    if (!verify)
        REQUIRE(symlink(target, "/mnt/renamed/long-link") == 0);
    REQUIRE(readlink("/mnt/renamed/long-link", readback, sizeof(readback)) == sizeof(target) - 1 &&
            !memcmp(readback, target, sizeof(target) - 1));
    if (!root)
        REQUIRE(umount("/mnt") == 0);
    puts(verify ? "EXT4_EXTENT_REBOOT_PASS" : "EXT4_EXTENT_MUTATION_PASS");
    return 0;
}

int main(void) {
    const char* phase = getenv("AXIOM64_PHASE");
    int status = phase ? exercise(phase) : 1;
    fflush(stdout);
    if (!status)
        reboot(RB_POWER_OFF);
    return 1;
}

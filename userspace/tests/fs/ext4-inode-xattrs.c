// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext4-inode-xattrs.c
 * @brief   Verify inode-body and external ext4 attributes through the Linux ABI.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Checks mixed attribute storage, replacement, overflow, and mount rejection.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#define REQUIRE(test)                                                                              \
    do {                                                                                           \
        if (!(test)) {                                                                             \
            printf("EXT4_INODE_XATTR_FAIL line=%d errno=%d %s\n", __LINE__, errno, #test);         \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static const char path[] = "/mnt/native";
static const char small[] = "user.small";
static const char kept[] = "user.kept";
static const char large[] = "user.large";

static int list_matches(int mixed) {
    char names[64] = "unchanged";
    size_t count = sizeof(small) + sizeof(kept) + (mixed ? sizeof(large) : 0);
    REQUIRE(listxattr(path, NULL, 0) == (ssize_t)count);
    REQUIRE(listxattr(path, names, count - 1) == -1 && errno == ERANGE &&
            !strcmp(names, "unchanged"));
    REQUIRE(listxattr(path, names, sizeof(names)) == (ssize_t)count);
    const char* expected[] = {small, kept, large};
    unsigned seen = 0;
    for (size_t offset = 0; offset < count;) {
        const char* name = names + offset;
        size_t length = strnlen(name, count - offset);
        REQUIRE(length < count - offset);
        unsigned index = 0;
        while (index < 3 && strcmp(name, expected[index]))
            ++index;
        REQUIRE(index < 3);
        unsigned bit = 1u << index;
        REQUIRE(!(seen & bit));
        seen |= bit;
        offset += length + 1;
    }
    REQUIRE(seen == (mixed ? 7 : 3));
    return 0;
}

static int mutate(void) {
    unsigned char value[4096], observed[240];
    for (size_t i = 0; i < sizeof(value); ++i)
        value[i] = i & 255;
    struct statfs fs;
    REQUIRE(statfs("/mnt", &fs) == 0 && fs.f_bsize >= 1024 && (size_t)fs.f_bsize <= sizeof(value));
    REQUIRE(list_matches(1) == 0);
    REQUIRE(getxattr(path, small, observed, sizeof(observed)) == 6 &&
            !memcmp(observed, "inline", 6));
    REQUIRE(getxattr(path, large, observed, sizeof(observed)) == sizeof(observed) &&
            !memcmp(observed, value, sizeof(observed)));
    REQUIRE(getxattr(path, kept, observed, sizeof(observed)) == 0);
    REQUIRE(setxattr(path, small, "noop", 4, XATTR_CREATE) == -1 && errno == EEXIST);
    REQUIRE(setxattr(path, large, "noop", 4, XATTR_CREATE) == -1 && errno == EEXIST);
    REQUIRE(setxattr(path, "user.missing", "noop", 4, XATTR_REPLACE) == -1 && errno == ENODATA);
    REQUIRE(setxattr(path, kept, "kept", 4, XATTR_REPLACE) == 0);
    REQUIRE(setxattr(path, small, "updated", 7, XATTR_REPLACE) == 0);
    REQUIRE(setxattr(path, small, value, fs.f_bsize - 128, XATTR_REPLACE) == -1 && errno == ENOSPC);
    REQUIRE(getxattr(path, small, observed, sizeof(observed)) == 7 &&
            !memcmp(observed, "updated", 7));
    REQUIRE(setxattr(path, small, value, 480, XATTR_REPLACE) == 0);
    REQUIRE(removexattr(path, large) == 0);
    return 0;
}

static int verify(void) {
    unsigned char observed[480];
    REQUIRE(list_matches(0) == 0);
    REQUIRE(getxattr(path, large, observed, sizeof(observed)) == -1 && errno == ENODATA);
    REQUIRE(getxattr(path, kept, observed, sizeof(observed)) == 4 && !memcmp(observed, "kept", 4));
    REQUIRE(getxattr(path, small, observed, sizeof(observed)) == sizeof(observed));
    for (size_t i = 0; i < sizeof(observed); ++i)
        REQUIRE(observed[i] == (i & 255));
    return 0;
}

static int verify_relocation(void) {
    unsigned char observed[480];
    REQUIRE(getxattr(path, small, observed, sizeof(observed)) == sizeof(observed));
    for (size_t i = 0; i < sizeof(observed); ++i)
        REQUIRE(observed[i] == (i & 255));
    REQUIRE(getxattr(path, large, observed, sizeof(observed)) == 240);
    for (size_t i = 0; i < 240; ++i)
        REQUIRE(observed[i] == i);
    REQUIRE(getxattr(path, kept, observed, sizeof(observed)) == 0);
    return 0;
}

static int interrupt_relocation(void) {
    unsigned char value[480];
    for (size_t i = 0; i < sizeof(value); ++i)
        value[i] = i & 255;
    REQUIRE(setxattr(path, small, value, sizeof(value), XATTR_REPLACE) == -1 && errno == EIO);
    REQUIRE(verify_relocation() == 0);
    puts("EXT4_INODE_XATTR_FAULT_ARMED");
    fflush(stdout);
    for (;;)
        pause();
}

int main(void) {
    const char* phase = getenv("AXIOM64_PHASE");
    REQUIRE(phase && mkdir("/mnt", 0755) == 0);
    if (!strcmp(phase, "invalid")) {
        REQUIRE(mount("/dev/vda", "/mnt", "ext4", 0, NULL) == -1 && errno == EUCLEAN);
        puts("EXT4_INODE_XATTR_REJECTION_PASS");
    } else if (!strcmp(phase, "pressure")) {
        REQUIRE(mount("/dev/vda", "/mnt", "ext4", 0, NULL) == 0);
        REQUIRE(interrupt_relocation() == 0);
    } else if (!strcmp(phase, "recovery")) {
        REQUIRE(mount("/dev/vda", "/mnt", "ext4", MS_RDONLY, NULL) == 0);
        REQUIRE(verify_relocation() == 0 && umount("/mnt") == 0);
        puts("EXT4_INODE_XATTR_RECOVERY_PASS");
    } else {
        int write = !strcmp(phase, "write");
        REQUIRE(write || !strcmp(phase, "verify"));
        REQUIRE(mount("/dev/vda", "/mnt", "ext4", write ? 0 : MS_RDONLY, NULL) == 0);
        REQUIRE(!write || !mutate());
        REQUIRE(!verify() && umount("/mnt") == 0);
        puts("EXT4_INODE_XATTR_PASS");
    }
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}

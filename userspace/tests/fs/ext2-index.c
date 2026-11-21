// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/ext2-index.c
 * @brief   Exercise indexed ext directory operations in the guest.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Uses native-created trees, then checks lookup, mutation, enumeration and reboot.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUIRE(test)                                                                              \
    do {                                                                                           \
        if (!(test)) {                                                                             \
            printf("EXT2_INDEX_FAIL line=%d errno=%d %s\n", __LINE__, errno, #test);               \
            fflush(stdout);                                                                        \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

enum { seed_count = 270, new_count = 660, converted_count = 50 };

static void name(char* result, const char* directory, char prefix, unsigned index) {
    size_t base = strlen(directory);
    memcpy(result, directory, base);
    int fixed =
        sprintf(result + base, "%s%c%04u-", index % 7 == 0 ? "\xc3\xa9" : "", prefix, index);
    size_t limit = 237 + index % 11;
    for (size_t i = fixed; i < limit; i++)
        result[base + i] = 'a' + index * 7 % 26;
    result[base + limit] = 0;
}

static int read_byte(const char* path, char expected) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return 0;
    char byte;
    int ok = read(fd, &byte, 1) == 1 && byte == expected && read(fd, &byte, 1) == 0;
    return close(fd) == 0 && ok;
}

static int collision(int verify) {
    const char* directory = "/mnt/target/collision";
    const unsigned rows[] = {1, 3, 41574, 59571, 0};
    if (!verify)
        REQUIRE(mkdir(directory, 0755) == 0);
    for (unsigned i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        char path[320], byte = '0' + i;
        int prefix = sprintf(path, "%s/x%07u-", directory, rows[i]);
        memset(path + prefix, 'z', 231);
        path[prefix + 231] = 0;
        if (!verify) {
            int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
            REQUIRE(fd >= 0 && write(fd, &byte, 1) == 1 && close(fd) == 0);
        }
        REQUIRE(read_byte(path, byte));
    }
    return 0;
}

static int guest(const char* phase) {
    REQUIRE(mkdir("/mnt", 0755) == 0);
    int negative = !strcmp(phase, "invalid");
    int verify = !strcmp(phase, "verify");
    int rc = mount("/dev/vda", "/mnt", "ext2", verify ? MS_RDONLY : 0, NULL);
    if (negative) {
        REQUIRE(rc == -1 && errno == EUCLEAN);
        puts("EXT2_INDEX_REJECT_PASS");
        return 0;
    }
    REQUIRE(rc == 0);
    char path[320], alternate[320];
    const char* initial = verify ? "/mnt/target/index/" : "/mnt/index/";
    for (unsigned i = 0; i < seed_count; i++) {
        name(path, initial, 's', i);
        if (verify && i == 1)
            REQUIRE(access(path, F_OK) == -1 && errno == ENOENT);
        else
            REQUIRE(read_byte(path, 's'));
    }
    const char* directory = "/mnt/target/index/";
    if (!verify) {
        REQUIRE(rename("/mnt/index", "/mnt/target/index") == 0);
        name(path, directory, 's', 1);
        REQUIRE(unlink(path) == 0);
        name(path, directory, 's', 0);
        REQUIRE(link(path, "/mnt/target/index/alias") == 0);
        for (unsigned i = 0; i < new_count; i++) {
            name(path, directory, 'n', i);
            int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
            REQUIRE(fd >= 0);
            REQUIRE(write(fd, "n", 1) == 1 && close(fd) == 0);
        }
        name(path, directory, 'n', 0);
        name(alternate, directory, 'n', 1);
        REQUIRE(rename(path, alternate) == 0);
    }
    REQUIRE(read_byte("/mnt/target/index/alias", 's'));
    for (unsigned i = 0; i < new_count; i++) {
        name(path, directory, 'n', i);
        if (i)
            REQUIRE(read_byte(path, 'n'));
        else
            REQUIRE(access(path, F_OK) == -1 && errno == ENOENT);
    }
    DIR* index = opendir(directory);
    REQUIRE(index);
    unsigned entries = 0;
    struct dirent* entry;
    while ((entry = readdir(index)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            entries++;
    REQUIRE(closedir(index) == 0 && entries == seed_count + new_count - 1);
    if (!verify)
        REQUIRE(mkdir("/mnt/target/converted", 0755) == 0);
    for (unsigned i = 0; i < converted_count; i++) {
        name(path, "/mnt/target/converted/", 'c', i);
        if (!verify) {
            int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
            REQUIRE(fd >= 0 && write(fd, "c", 1) == 1 && close(fd) == 0);
        }
        REQUIRE(read_byte(path, 'c'));
    }
    REQUIRE(collision(verify) == 0);
    REQUIRE(umount("/mnt") == 0);
    puts(verify ? "EXT2_INDEX_REBOOT_PASS" : "EXT2_INDEX_MUTATE_PASS");
    return 0;
}

int main(void) {
    const char* phase = getenv("AXIOM64_PHASE");
    int status = phase ? guest(phase) : 1;
    fflush(stdout);
    if (!status)
        reboot(RB_POWER_OFF);
    return 1;
}

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/security/account-store-reboot.c
 * @brief   Account store reboot test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks persisted account state when the filesystem is reopened after reboot.
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
#include "../../accounts/store.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "ACCOUNT_STORE_REBOOT_FAIL line=%d errno=%d\n", __LINE__, errno);      \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

int main(int argc, char** argv) {
    CHECK(argc == 2 && !geteuid() && !getegid());
    char path[4096], passwd[4096], shadow[4096];
    CHECK(snprintf(path, sizeof(path), "%s/db", argv[1]) < (int)sizeof(path));
    CHECK(snprintf(passwd, sizeof(passwd), "%s/current/passwd", path) < (int)sizeof(passwd));
    CHECK(snprintf(shadow, sizeof(shadow), "%s/current/shadow", path) < (int)sizeof(shadow));
    struct account_store* store = NULL;
    CHECK(account_store_begin(path, 0, &store) == 0);
    const struct account_content* files = account_store_snapshot(store);
    CHECK(files);
    const char* expected[ACCOUNT_FILE_COUNT] = {
        "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000:epoch13:/home/alice:/bin/sh\n",
        "root:x:0:\nusers:x:1000:alice\nepoch13:x:1001:\n",
        "root:!:1:0:99999:7:::\nalice:!:13:0:99999:7:::\n"};
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        CHECK(files[i].size == strlen(expected[i]) &&
              !memcmp(files[i].data, expected[i], files[i].size));
    account_store_end(store);
    struct stat value;
    CHECK(stat(shadow, &value) == 0 && value.st_uid == 0 && value.st_gid == 0 &&
          (value.st_mode & 07777) == 0600 && S_ISREG(value.st_mode) && value.st_nlink == 1);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgroups(0, NULL) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
        int fd = open(passwd, O_RDONLY);
        CHECK(fd >= 0);
        char data[256];
        ssize_t count = read(fd, data, sizeof(data));
        CHECK(count == (ssize_t)strlen(expected[0]) && !memcmp(data, expected[0], (size_t)count));
        CHECK(close(fd) == 0 && open(shadow, O_RDONLY) < 0 && errno == EACCES);
        CHECK(account_store_begin(path, 1, &store) < 0 && errno == EPERM && !store);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("ACCOUNT_STORE_REBOOT_PASS epoch=13 files=3 ordinary_denials=2");
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/security/account-observe.c
 * @brief   Account state observer.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Reports selected account, credential, and session state for the test harness.
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
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "ACCOUNT_AUTH_FAIL observer-line=%d errno=%d\n", __LINE__, errno);     \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(int argc, char** argv) {
    uid_t real, effective, saved;
    gid_t gr, ge, gs;
    CHECK(getresuid(&real, &effective, &saved) == 0 && getresgid(&gr, &ge, &gs) == 0);
    if (argc == 2 && !strcmp(argv[1], "--privileged-control")) {
        CHECK(real == 1001 && effective == 0 && saved == 0);
        CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
        puts("ACCOUNT_SETUID_CONTROL_PASS real=1001 effective=0 saved=0");
        return 0;
    }
    CHECK(argc == 4 && !strcmp(argv[1], "--service-observe"));
    CHECK(real == 1001 && effective == 1001 && saved == 1001 && (uid_t)setfsuid((uid_t)-1) == 1001);
    CHECK(gr == 1001 && ge == 1001 && gs == 1001 && (gid_t)setfsgid((gid_t)-1) == 1001);
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    CHECK(!getenv("LD_PRELOAD") && !getenv("LD_LIBRARY_PATH") && !getenv("EVIL_FIXTURE_ENV"));
    CHECK(getenv("USER") && !strcmp(getenv("USER"), "bob") && getenv("LOGNAME") &&
          !strcmp(getenv("LOGNAME"), "bob"));
    CHECK(getenv("HOME") && !strcmp(getenv("HOME"), argv[2]) && getenv("PATH") &&
          !strcmp(getenv("PATH"), "/usr/local/bin:/usr/bin:/bin"));
    char cwd[4096];
    CHECK(getcwd(cwd, sizeof(cwd)) && !strcmp(cwd, argv[2]));
    CHECK((umask(077) & 0777) == 077);
    CHECK(open(argv[3], O_RDONLY) < 0 && errno == EACCES);
    CHECK(setuid(0) < 0 && errno == EPERM && setgid(0) < 0 && errno == EPERM);
    puts("ACCOUNT_SERVICE_EXEC_PASS uid=1001 gid=1001 no_new_privileges=1 private_file_denied=1");
    return 0;
}

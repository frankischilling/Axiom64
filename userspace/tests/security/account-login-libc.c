// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utmpx.h>

_Static_assert(sizeof(struct utmpx) == 384, "Native GNU utmp ABI");
_Static_assert(offsetof(struct utmpx, ut_session) == 336, "Native GNU session field");

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_LOGIN_LIBC_FAIL line=%d errno=%d expression=%s\n", __LINE__,  \
                    errno, #expression);                                                           \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

int main(int argc, char** argv) {
    CHECK(argc == 2);
    const char* names[] = {"utmp", "wtmp", "btmp"};
    unsigned totals[3] = {0}, users = 0, dead = 0, boot = 0;
    for (unsigned file = 0; file < 3; file++) {
        char path[4096];
        CHECK(snprintf(path, sizeof(path), "%s/%s", argv[1], names[file]) < (int)sizeof(path));
        CHECK(utmpxname(path) == 0);
        setutxent();
        struct utmpx* entry;
        while ((entry = getutxent())) {
            totals[file]++;
            CHECK(entry->ut_tv.tv_usec >= 0 && entry->ut_tv.tv_usec < 1000000);
            if (file == 0)
                CHECK(entry->ut_type == DEAD_PROCESS && !entry->ut_user[0]);
            else if (file == 1) {
                if (entry->ut_type == USER_PROCESS) {
                    CHECK(!strncmp(entry->ut_user, "alice", 32));
                    CHECK(entry->ut_pid > 0 && entry->ut_session == entry->ut_pid);
                    users++;
                } else if (entry->ut_type == DEAD_PROCESS) {
                    CHECK(!entry->ut_user[0]);
                    dead++;
                } else {
                    CHECK(entry->ut_type == BOOT_TIME);
                    boot++;
                }
            } else
                CHECK(entry->ut_type == LOGIN_PROCESS && !strncmp(entry->ut_user, "missing", 32));
        }
        endutxent();
    }
    CHECK(totals[0] >= 1 && totals[1] == 5 && totals[2] == 1);
    CHECK(users == 2 && dead == 2 && boot == 1);
    printf("ACCOUNT_LOGIN_LIBC_PASS utmp=%u wtmp=5 btmp=1 users=2 dead=2 boot=1\n", totals[0]);
    return 0;
}

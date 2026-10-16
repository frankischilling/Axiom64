// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/logbook_internal.h"
#include <errno.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "ACCOUNT_ROTATION_HOLDERS_FAIL line=%d errno=%d expression=%s\n",      \
                    __LINE__, errno, #expression);                                                 \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static pid_t session(int* finish) {
    int control[2], ready[2];
    CHECK(pipe(control) == 0 && pipe(ready) == 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (!pid) {
        close(control[1]);
        close(ready[0]);
        CHECK(setsid() == getpid());
        CHECK(setgroups(0, NULL) == 0 && setresgid(1000, 1000, 1000) == 0 &&
              setresuid(1000, 1000, 1000) == 0);
        CHECK(write(ready[1], "x", 1) == 1);
        char value;
        _exit(read(control[0], &value, 1) == 1 ? 0 : 1);
    }
    close(control[0]);
    close(ready[1]);
    char value;
    CHECK(read(ready[0], &value, 1) == 1 && close(ready[0]) == 0);
    *finish = control[1];
    return pid;
}

int main(int argc, char** argv) {
    CHECK(argc == 2 && !geteuid() && !getegid());
    CHECK(ACCOUNT_LOGIN_JOURNAL_LIMIT / sizeof(struct account_login_frame) == 8);
    struct account_logbook* book = NULL;
    CHECK(account_logbook_open(argv[1], 1, &book) == 0);
    account_logbook_close(book);
    int finish[2];
    pid_t children[2] = {session(&finish[0]), session(&finish[1])};
    int published[2], gone[2];
    CHECK(pipe(published) == 0 && pipe(gone) == 0);
    pid_t manager = fork();
    CHECK(manager >= 0);
    if (!manager) {
        close(published[0]);
        close(gone[0]);
        struct account_profile profile = {.name = "alice", .uid = 1000, .gid = 1000};
        struct account_session_lease* leases[2];
        CHECK(account_logbook_open(argv[1], 0, &book) == 0);
        CHECK(account_logbook_begin(book, &profile, children[0], "/dev/pts/1", &leases[0]) == 0);
        CHECK(account_logbook_begin(book, &profile, children[1], "/dev/pts/2", &leases[1]) == 0);
        for (int i = 0; i < 20; i++)
            CHECK(account_logbook_audit(book, ACCOUNT_LOGIN_SUDO, "alice", 1000, "root", "tty",
                                        i) == 0);
        CHECK(book->state.generation == 4 && book->count == 4);
        account_logbook_close(book);
        pid_t holder = fork();
        CHECK(holder >= 0);
        if (!holder) {
            close(published[1]);
            // This second holder keeps the same open file descriptions alive.
            // The original supervisor's death must not recover either lease.
            for (;;)
                pause();
        }
        close(gone[1]);
        CHECK(write(published[1], &holder, sizeof(holder)) == sizeof(holder));
        for (;;)
            pause();
    }
    close(published[1]);
    close(gone[1]);
    pid_t holder;
    CHECK(read(published[0], &holder, sizeof(holder)) == sizeof(holder) &&
          close(published[0]) == 0);
    CHECK(kill(manager, SIGKILL) == 0);
    int status;
    CHECK(waitpid(manager, &status, 0) == manager && WIFSIGNALED(status));
    CHECK(account_logbook_open(argv[1], 0, &book) == 0 && book->state.generation == 4 &&
          account_logbook_active(book, 1000) == 1 && book->count == 4);
    account_logbook_close(book);
    CHECK(kill(holder, SIGKILL) == 0);
    char value;
    CHECK(read(gone[0], &value, 1) == 0 && close(gone[0]) == 0);
    CHECK(account_logbook_open(argv[1], 0, &book) == 0 && account_logbook_active(book, 1000) == 0);
    CHECK(book->count == 6 && book->frames[4].kind == ACCOUNT_LOGIN_RECOVERED &&
          book->frames[5].kind == ACCOUNT_LOGIN_RECOVERED &&
          book->state.previous_events + book->count - book->state.carried == 24);
    account_logbook_close(book);
    CHECK(account_logbook_open(argv[1], 0, &book) == 0 && book->count == 6);
    account_logbook_close(book);
    for (unsigned i = 0; i < 2; i++) {
        CHECK(write(finish[i], "x", 1) == 1 && close(finish[i]) == 0);
        CHECK(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0);
    }
    puts("ACCOUNT_ROTATION_HOLDERS_PASS generations=4 leases=2 recovered=2 global_events=24");
    return 0;
}

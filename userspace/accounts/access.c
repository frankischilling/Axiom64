// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "auth.h"
#include "database.h"
#include "logbook.h"
#include "password.h"
#include "recorded.h"
#include "secret.h"
#include "session.h"
#include "update.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#ifndef ACCOUNT_DATABASE_PATH
#define ACCOUNT_DATABASE_PATH "/etc/axiom64/accounts"
#endif
#ifndef ACCOUNT_RECORDS_PATH
#define ACCOUNT_RECORDS_PATH "/var/log/axiom64/login"
#endif

static int failed(int error) {
    errno = error;
    return -1;
}

static void usage(void) {
    fputs("usage: account-access [--database PATH] [--records PATH] COMMAND\n"
          "  login [NAME] | su [NAME] [-c COMMAND] | sudo [-u NAME] COMMAND...\n"
          "  passwd [NAME] | provision NAME HOME SHELL\n",
          stderr);
}

static int public_name(int terminal, char name[ACCOUNT_NAME_MAX + 1]) {
    if (dprintf(terminal, "login: ") < 0)
        return -1;
    size_t used = 0;
    int invalid = 0;
    for (;;) {
        char byte;
        ssize_t count = read(terminal, &byte, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return failed(count ? errno : EIO);
        if (byte == '\n')
            break;
        if (!byte || byte == '\r' || used == ACCOUNT_NAME_MAX)
            invalid = 1;
        else if (!invalid)
            name[used++] = byte;
    }
    name[used] = 0;
    return invalid || !account_name_valid(name) ? failed(EINVAL) : 0;
}

static int new_password(int terminal, char secret[ACCOUNT_PASSWORD_MAX + 1]) {
    char confirmation[ACCOUNT_PASSWORD_MAX + 1] = {0};
    int error = account_secret_read(terminal, "New password: ", secret) < 0 ? errno : 0;
    if (!error && account_secret_read(terminal, "Confirm password: ", confirmation) < 0)
        error = errno;
    if (!error && (!*secret || strcmp(secret, confirmation)))
        error = EINVAL;
    account_password_clear(confirmation, sizeof(confirmation));
    if (error)
        account_password_clear(secret, ACCOUNT_PASSWORD_MAX + 1);
    return error ? failed(error) : 0;
}

static int denied(const char* records, const char* name, const char* terminal) {
    struct account_logbook* book = NULL;
    if (account_logbook_open(records, 1, &book) < 0)
        return -1;
    int result = account_logbook_audit(book, ACCOUNT_LOGIN_DENIED,
                                       account_name_valid(name) ? name : "invalid", (uid_t)-1, NULL,
                                       terminal, EACCES);
    int error = errno;
    account_logbook_close(book);
    return result < 0 ? failed(error) : 0;
}

static int authenticate(const char* database, const char* records, const char* name, int terminal,
                        const char* tty, int sudo, int finish_change,
                        struct account_profile** profile) {
    char secret[ACCOUNT_PASSWORD_MAX + 1] = {0};
    int error = account_secret_read(terminal, "Password: ", secret) < 0 ? errno : 0;
    int result = !error ? account_auth_password(database, name, secret, sudo, profile) : -1;
    if (result < 0 && !error)
        error = errno;
    account_password_clear(secret, sizeof(secret));
    if (!error && result == ACCOUNT_AUTH_DENIED) {
        if (denied(records, name, tty) < 0)
            return -1;
        dprintf(terminal, "Authentication failed.\n");
        return failed(EACCES);
    }
    if (!error && result == ACCOUNT_AUTH_CHANGE_REQUIRED && finish_change) {
        dprintf(terminal, "A password change is required.\n");
        int published = 0;
        if (new_password(terminal, secret) < 0 ||
            account_password_update(database, records, *profile, *profile, secret, &published) < 0)
            error = errno;
        if (published)
            dprintf(terminal, "Password update is visible.\n");
        if (!error) {
            account_profile_free(*profile);
            *profile = NULL;
            result = account_auth_password(database, name, secret, sudo, profile);
            if (result != ACCOUNT_AUTH_ACCEPTED)
                error = result < 0 ? errno : EACCES;
        }
        account_password_clear(secret, sizeof(secret));
    }
    return error ? failed(error) : 0;
}

static int controlling_terminal(char tty[64]) {
    // Compare actual terminal nodes, not Linux's separate /dev/tty alias inode.
    for (int fd = 0; fd < 3; fd++) {
        struct stat source, opened;
        if (tcgetsid(fd) != getsid(0) || tcgetpgrp(fd) != getpgrp() ||
            ttyname_r(fd, tty, 64) != 0 || fstat(fd, &source) < 0)
            continue;
        int terminal = open(tty, O_RDWR | O_NOCTTY | O_CLOEXEC | O_NOFOLLOW);
        if (terminal < 0)
            return -1;
        if (fstat(terminal, &opened) < 0 || source.st_dev != opened.st_dev ||
            source.st_ino != opened.st_ino) {
            close(terminal);
            return failed(ESTALE);
        }
        return terminal;
    }
    strcpy(tty, "/dev/tty");
    return open(tty, O_RDWR | O_NOCTTY | O_CLOEXEC);
}

static int actor_name(const char* database, uid_t uid, char name[ACCOUNT_NAME_MAX + 1]) {
    struct account_database* db = NULL;
    if (account_database_begin(database, 0, &db) < 0)
        return -1;
    const struct account_user* user = account_database_uid(db, uid);
    int error = !user ? ENOENT : 0;
    if (!error)
        strcpy(name, user->name);
    account_database_end(db);
    return error ? failed(error) : 0;
}

static int streams(int terminal, unsigned* mask) {
    struct stat source;
    if (fstat(terminal, &source) < 0)
        return -1;
    *mask = 0;
    for (int fd = 0; fd < 3; fd++) {
        struct stat destination;
        if (fstat(fd, &destination) < 0) {
            if (errno != EBADF)
                return -1;
            int replacement = open("/dev/null", fd ? O_WRONLY : O_RDONLY);
            if (replacement < 0)
                return -1;
            if (replacement != fd) {
                int error = dup2(replacement, fd) < 0 ? errno : 0;
                close(replacement);
                if (error)
                    return failed(error);
            }
        } else if (S_ISCHR(destination.st_mode) && source.st_dev == destination.st_dev &&
                   source.st_ino == destination.st_ino)
            *mask |= 1u << fd;
    }
    return 0;
}

int main(int argc, char** argv) {
    uid_t caller = getuid();
    if (geteuid()) {
        fputs("account-access: privileged installation is required\n", stderr);
        return 1;
    }
    const char* database = ACCOUNT_DATABASE_PATH;
    const char* records = ACCOUNT_RECORDS_PATH;
    int first = 1;
    while (!caller && argc > first + 2 &&
           (!strcmp(argv[first], "--database") || !strcmp(argv[first], "--records"))) {
        if (!strcmp(argv[first], "--database"))
            database = argv[first + 1];
        else
            records = argv[first + 1];
        first += 2;
    }
    if (argc <= first) {
        usage();
        return 2;
    }
    const char* mode = argv[first++];
    int login = !strcmp(mode, "login"), su = !strcmp(mode, "su"), sudo = !strcmp(mode, "sudo");
    int passwd = !strcmp(mode, "passwd"), provision = !strcmp(mode, "provision");
    if ((!login && !su && !sudo && !passwd && !provision) || (caller && (login || provision))) {
        usage();
        return 2;
    }
    char term[33] = {0};
    const char* inherited_term = getenv("TERM");
    if (inherited_term && strlen(inherited_term) <= 32)
        strcpy(term, inherited_term);
    if (setgroups(0, NULL) < 0 || setresgid(0, 0, 0) < 0 || setresuid(0, 0, 0) < 0 ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0 || clearenv() < 0) {
        perror("account-access: privilege setup");
        return 1;
    }
    umask(077);
    char tty[64];
    int terminal = controlling_terminal(tty);
    int error = terminal < 0 ? errno : 0;
    if (!error && (tcgetsid(terminal) != getsid(0) || tcgetpgrp(terminal) != getpgrp()))
        error = ENOTTY;
    const char* target = "root";
    char name[ACCOUNT_NAME_MAX + 1] = {0}, actor[ACCOUNT_NAME_MAX + 1] = {0};
    if (!error && provision) {
        char secret[ACCOUNT_PASSWORD_MAX + 1] = {0};
        int published = 0;
        if (argc - first != 3)
            error = EINVAL;
        else if (new_password(terminal, secret) < 0 ||
                 account_bootstrap(database, records, argv[first], argv[first + 1], argv[first + 2],
                                   secret, &published) < 0)
            error = errno;
        account_password_clear(secret, sizeof(secret));
        if (published)
            dprintf(terminal, "Administrator account is visible.\n");
        goto done;
    }
    if (!error && actor_name(database, caller, actor) < 0)
        error = errno;
    if (!error && login) {
        if (argc - first > 1)
            error = EINVAL;
        else if (argc == first && public_name(terminal, name) < 0)
            error = errno;
        else
            target = argc == first ? name : argv[first];
    } else if (!error && (su || passwd)) {
        target = passwd ? actor : "root";
        if (argc > first && strcmp(argv[first], "-c"))
            target = argv[first++];
        if (passwd && (argc != first || (caller && strcmp(target, actor))))
            error = EACCES;
    } else if (!error && sudo) {
        if (argc > first + 1 && !strcmp(argv[first], "-u")) {
            target = argv[first + 1];
            first += 2;
        }
        if (argc == first)
            error = EINVAL;
    }
    if (!error && !account_name_valid(target))
        error = EINVAL;
    struct account_profile *profile = NULL, *authorization = NULL;
    if (!error && sudo && caller &&
        authenticate(database, records, actor, terminal, tty, 1, 1, &authorization) < 0)
        error = errno;
    if (!error) {
        if (login || (caller && !sudo)) {
            if (authenticate(database, records, target, terminal, tty, 0, !passwd, &profile) < 0)
                error = errno;
        } else if (account_auth_root_switch(database, target, &profile) < 0)
            error = errno;
    }
    if (!error && passwd) {
        char secret[ACCOUNT_PASSWORD_MAX + 1] = {0};
        int published = 0;
        if (new_password(terminal, secret) < 0 ||
            account_password_update(database, records, profile, caller ? profile : NULL, secret,
                                    &published) < 0)
            error = errno;
        account_password_clear(secret, sizeof(secret));
        if (published)
            dprintf(terminal, "Password update is visible.\n");
    } else if (!error) {
        char* shell[] = {profile->shell, "-l", NULL, NULL, NULL};
        char** command = shell;
        if (su && argc > first) {
            if (argc - first != 2 || strcmp(argv[first], "-c"))
                error = EINVAL;
            else {
                shell[2] = "-c";
                shell[3] = argv[first + 1];
            }
        } else if (sudo)
            command = argv + first;
        struct account_recorded_session context = {.database = database,
                                                   .records = records,
                                                   .target = profile,
                                                   .authorization = authorization,
                                                   .actor = caller,
                                                   .operation = sudo ? ACCOUNT_LOGIN_SUDO
                                                                : su ? ACCOUNT_LOGIN_SU
                                                                     : ACCOUNT_LOGIN_START};
        struct account_session_events events = {account_recorded_begin, account_recorded_end,
                                                &context};
        unsigned mask = 7;
        int status = 0;
        if (!error && sudo && streams(terminal, &mask) < 0)
            error = errno;
        if (!error && account_session_run_stdio(profile, terminal, *term ? term : NULL, mask,
                                                command, &events, &status) < 0)
            error = errno;
        if (!error) {
            account_profile_free(profile);
            account_profile_free(authorization);
            close(terminal);
            return WIFEXITED(status)     ? WEXITSTATUS(status)
                   : WIFSIGNALED(status) ? 128 + WTERMSIG(status)
                                         : 1;
        }
    }
    account_profile_free(profile);
    account_profile_free(authorization);
done:
    if (terminal >= 0)
        close(terminal);
    if (error) {
        errno = error;
        perror("account-access");
    }
    return error ? 1 : 0;
}

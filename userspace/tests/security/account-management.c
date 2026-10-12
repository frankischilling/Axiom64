// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/database.h"
#include "../../accounts/password.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "ACCOUNT_MANAGEMENT_FAIL line=%d errno=%d\n", __LINE__, errno);        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static const char secret[] = "Fixture-only-Administrator-42";

static void observe(const char* name) {
    printf("ACCOUNT_MANAGEMENT_OBSERVATION case=%s\n", name);
    observations++;
}

static void command(char* const* arguments, int expected, int password, int ordinary) {
    int descriptors[2];
    CHECK(pipe(descriptors) == 0);
    if (password) {
        CHECK(write(descriptors[1], secret, sizeof(secret) - 1) == (ssize_t)sizeof(secret) - 1);
        CHECK(write(descriptors[1], "\n", 1) == 1);
    }
    CHECK(close(descriptors[1]) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(dup2(descriptors[0], 0) == 0);
        close(descriptors[0]);
        if (ordinary)
            CHECK(setgroups(0, NULL) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
        size_t count = 0;
        while (arguments[count])
            count++;
        CHECK(count < 32);
        char* registered[36];
        registered[0] = arguments[0];
        registered[1] = "--records";
        registered[2] = "/run/accounts/records";
        for (size_t i = 1; i <= count; i++)
            registered[i + 2] = arguments[i];
        execv("/bin/accountctl", registered);
        _exit(99);
    }
    close(descriptors[0]);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == expected);
}

int main(void) {
    CHECK(!getuid() && !geteuid() && !getegid());
    const char* path = "/run/accounts/db";
    CHECK(mkdir("/run/accounts", 0755) == 0);
    command((char*[]){"accountctl", "--database", (char*)path, "bootstrap", "admin", "/home/admin",
                      "/bin/sh", "--password-fd", "0", NULL},
            0, 1, 0);
    observe("real-private-administrator-provisioning");
    struct stat value;
    CHECK(stat("/home/admin", &value) == 0 && value.st_uid == 1000 && value.st_gid == 1000 &&
          (value.st_mode & 07777) == 0700);
    observe("private-home-ownership");
    struct account_database* db = NULL;
    CHECK(account_database_begin(path, 0, &db) == 0);
    const struct account_user* admin = account_database_user(db, "admin");
    CHECK(admin && admin->uid == 1000 && admin->gid == 1000 && !strncmp(admin->password, "$y$", 3));
    CHECK(account_password_verify(secret, admin->password) == 1);
    CHECK(account_password_verify("wrong-fixture-password", admin->password) == 0);
    CHECK(account_password_verify(secret, account_database_user(db, "root")->password) == 0);
    account_database_end(db);
    observe("maintained-hash-correct-wrong-and-locked-controls");
    command((char*[]){"accountctl", "--database", (char*)path, "bootstrap", "other", "/home/other",
                      "/bin/sh", "--password-fd", "0", NULL},
            1, 1, 0);
    observe("later-provisioning-denied");
    command((char*[]){"accountctl", "--database", (char*)path, "group-add", "bob", "1001", NULL}, 0,
            0, 0);
    command((char*[]){"accountctl", "--database", (char*)path, "user-add", "bob", "1001", "bob",
                      "/home/bob", "/bin/sh", NULL},
            0, 0, 0);
    command((char*[]){"accountctl", "--database", (char*)path, "member-add", "sudo", "bob", NULL},
            0, 0, 0);
    command((char*[]){"accountctl", "--database", (char*)path, "user-rename", "bob", "carol", NULL},
            0, 0, 0);
    observe("actual-account-group-and-rename-commands");
    command((char*[]){"accountctl", "--database", (char*)path, "user-add", "duplicate", "1001",
                      "bob", "/home/duplicate", "/bin/sh", NULL},
            1, 0, 0);
    command((char*[]){"accountctl", "--database", (char*)path, "group-delete", "bob", NULL}, 1, 0,
            0);
    observe("duplicate-and-primary-group-command-denials");
    command((char*[]){"accountctl", "--database", (char*)path, "password", "carol", "--password-fd",
                      "0", NULL},
            0, 1, 0);
    command((char*[]){"accountctl", "--database", (char*)path, "lock", "carol", NULL}, 0, 0, 0);
    CHECK(account_database_begin(path, 0, &db) == 0);
    CHECK(account_password_verify(secret, account_database_user(db, "carol")->password) == 0);
    account_database_end(db);
    command((char*[]){"accountctl", "--database", (char*)path, "unlock", "carol", NULL}, 0, 0, 0);
    CHECK(account_database_begin(path, 0, &db) == 0);
    CHECK(account_password_verify(secret, account_database_user(db, "carol")->password) == 1);
    account_database_end(db);
    observe("password-change-lock-and-unlock");
    command((char*[]){"accountctl", "--database", (char*)path, "group-add", "attack", "2000", NULL},
            1, 0, 1);
    observe("ordinary-administration-command-denied");
    for (const char** name = (const char*[]){"passwd", "group", "shadow", NULL}; *name; name++) {
        char target[256], link[64];
        CHECK(snprintf(target, sizeof(target), "%s/current/%s", path, *name) < (int)sizeof(target));
        CHECK(snprintf(link, sizeof(link), "/etc/%s", *name) < (int)sizeof(link));
        CHECK(symlink(target, link) == 0);
    }
    struct passwd pw, *user;
    struct group gr, *group;
    struct spwd sp, *shadow;
    char buffer[2048];
    CHECK(getpwnam_r("admin", &pw, buffer, sizeof(buffer), &user) == 0 && user &&
          pw.pw_uid == 1000 && pw.pw_gid == 1000);
    CHECK(getgrnam_r("sudo", &gr, buffer, sizeof(buffer), &group) == 0 && group && gr.gr_gid == 27);
    CHECK(getspnam_r("admin", &sp, buffer, sizeof(buffer), &shadow) == 0 && shadow &&
          !strncmp(sp.sp_pwdp, "$y$", 3));
    CHECK(getpwnam_r("missing", &pw, buffer, sizeof(buffer), &user) == 0 && !user);
    observe("actual-libc-name-group-shadow-and-missing-lookups");
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(initgroups("admin", 1000) == 0);
        gid_t groups[4];
        int count = getgroups(4, groups), found_primary = 0, found_sudo = 0;
        CHECK(count == 2);
        for (int i = 0; i < count; i++) {
            found_primary += groups[i] == 1000;
            found_sudo += groups[i] == 27;
        }
        CHECK(found_primary == 1 && found_sudo == 1);
        CHECK(setgid(1000) == 0 && setuid(1000) == 0);
        CHECK(getpwnam_r("admin", &pw, buffer, sizeof(buffer), &user) == 0 && user &&
              pw.pw_uid == 1000);
        CHECK(getspnam_r("admin", &sp, buffer, sizeof(buffer), &shadow) != 0 && !shadow);
        CHECK(setuid(0) < 0 && errno == EPERM);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    observe("real-initgroups-ordinary-lookup-shadow-denial-and-drop");
    command((char*[]){"accountctl", "--database", (char*)path, "user-delete", "carol", NULL}, 0, 0,
            0);
    command((char*[]){"accountctl", "--database", (char*)path, "group-delete", "bob", NULL}, 0, 0,
            0);
    CHECK(stat("/home/bob", &value) == 0 && value.st_uid == 1001);
    observe("account-deletion-preserves-home-data");
    printf("ACCOUNT_MANAGEMENT_PASS observations=%u\n", observations);
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/auth.h"
#include "../../accounts/database.h"
#include "../../accounts/home.h"
#include "../../accounts/password.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "ACCOUNT_AUTH_FAIL line=%d errno=%d\n", __LINE__, errno);              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static const char secret[] = "Fixture-only-Authentication-57";

static void observed(const char* name) {
    printf("ACCOUNT_AUTH_OBSERVATION case=%s\n", name);
    observations++;
}

static void wait_child(pid_t child) {
    int status;
    CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == 0);
}

static void age(const char* path, int64_t last, int64_t maximum, int64_t inactive, int64_t expiry) {
    struct account_database* db = NULL;
    CHECK(account_database_begin(path, 0, &db) == 0);
    struct account_user user = *account_database_user(db, "alice");
    user.age[0] = last;
    user.age[2] = maximum;
    user.age[4] = inactive;
    user.age[5] = expiry;
    CHECK(account_database_put_user(db, "alice", &user) == 0);
    int published;
    CHECK(account_database_commit(db, &published) == 0 && published);
    account_database_end(db);
}

static void denial(const char* path, const char* name, const char* password, int sudo) {
    struct account_profile* profile = NULL;
    CHECK(account_auth_password(path, name, password, sudo, &profile) == ACCOUNT_AUTH_DENIED &&
          !profile);
}

static void ids(uid_t uid, gid_t gid) {
    uid_t real, effective, saved;
    gid_t gr, ge, gs;
    CHECK(getresuid(&real, &effective, &saved) == 0 && getresgid(&gr, &ge, &gs) == 0);
    CHECK(real == uid && effective == uid && saved == uid && (uid_t)setfsuid((uid_t)-1) == uid);
    CHECK(gr == gid && ge == gid && gs == gid && (gid_t)setfsgid((gid_t)-1) == gid);
}

int main(int argc, char** argv) {
    CHECK(argc == 3 && !getuid() && !geteuid() && !getegid());
    CHECK(mkdir(argv[1], 0755) == 0 || errno == EEXIST);
    CHECK(chmod(argv[1], 0755) == 0);
    char path[4096], alice_home[4096], bob_home[4096], private_file[4096];
    CHECK(snprintf(path, sizeof(path), "%s/db", argv[1]) < (int)sizeof(path));
    CHECK(snprintf(alice_home, sizeof(alice_home), "%s/alice", argv[1]) < (int)sizeof(alice_home));
    CHECK(snprintf(bob_home, sizeof(bob_home), "%s/bob", argv[1]) < (int)sizeof(bob_home));
    CHECK(snprintf(private_file, sizeof(private_file), "%s/private", alice_home) <
          (int)sizeof(private_file));
    struct account_home* created[2] = {NULL, NULL};
    CHECK(account_home_create(alice_home, 1000, 1000, &created[0]) == 0 && created[0]);
    CHECK(account_home_create(bob_home, 1001, 1001, &created[1]) == 0 && created[1]);
    int fd = open(private_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    CHECK(fd >= 0 && write(fd, "private", 7) == 7 && fchown(fd, 1000, 1000) == 0 && close(fd) == 0);
    struct account_database* db = NULL;
    CHECK(account_database_begin(path, 1, &db) == 0);
    struct account_group group = {"alice", 1000, NULL, 0};
    CHECK(account_database_put_group(db, NULL, &group) == 0);
    group = (struct account_group){"bob", 1001, NULL, 0};
    CHECK(account_database_put_group(db, NULL, &group) == 0);
    group = (struct account_group){"sudo", 27, NULL, 0};
    CHECK(account_database_put_group(db, NULL, &group) == 0);
    char encoded[ACCOUNT_PASSWORD_HASH_SIZE];
    CHECK(account_password_hash(secret, encoded) == 0);
    int64_t today = (int64_t)time(NULL) / 86400;
    struct account_user user = {"alice", encoded, "Alice fixture",           alice_home, "/bin/sh",
                                1000,    1000,    {today, 0, -1, -1, -1, -1}};
    CHECK(account_database_put_user(db, NULL, &user) == 0);
    user = (struct account_user){"bob",     encoded, "Bob fixture", bob_home,
                                 "/bin/sh", 1001,    1001,          {today, 0, -1, -1, -1, -1}};
    CHECK(account_database_put_user(db, NULL, &user) == 0);
    CHECK(account_database_member(db, "sudo", "alice", 1) == 0);
    int published;
    CHECK(account_database_commit(db, &published) == 0 && published);
    for (unsigned i = 0; i < 2; i++)
        CHECK(account_home_finish(created[i], published) == 0);
    account_database_end(db);
    account_password_clear(encoded, sizeof(encoded));
    struct account_profile* profile = NULL;
    CHECK(account_auth_password(path, "alice", secret, 1, &profile) == ACCOUNT_AUTH_ACCEPTED &&
          profile);
    CHECK(profile->uid == 1000 && profile->gid == 1000 && profile->group_count == 2);
    account_profile_free(profile);
    observed("password-and-explicit-sudo-membership");
    denial(path, "alice", "wrong", 0);
    denial(path, "missing", secret, 0);
    denial(path, "root", secret, 0);
    denial(path, "bob", secret, 1);
    observed("wrong-missing-locked-and-disabled-elevation-denials");
    age(path, today, -1, -1, today);
    denial(path, "alice", secret, 0);
    observed("account-expiration");
    age(path, today - 5, 1, 1, -1);
    denial(path, "alice", secret, 0);
    observed("expired-password-inactivity");
    age(path, 0, -1, -1, -1);
    CHECK(account_auth_password(path, "alice", secret, 0, &profile) ==
              ACCOUNT_AUTH_CHANGE_REQUIRED &&
          profile);
    CHECK(profile->password_change_required && account_profile_enter(profile, 0) < 0 &&
          errno == EACCES);
    ids(0, 0);
    account_profile_free(profile);
    observed("forced-change-cannot-launch-session");
    age(path, today - 2, 1, -1, -1);
    CHECK(account_auth_password(path, "alice", secret, 0, &profile) ==
              ACCOUNT_AUTH_CHANGE_REQUIRED &&
          profile);
    account_profile_free(profile);
    observed("maximum-password-age");
    age(path, today, -1, -1, -1);
    CHECK(account_auth_password(path, "alice", secret, 0, &profile) == ACCOUNT_AUTH_ACCEPTED &&
          profile);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(account_profile_enter(profile, 0) == 0);
        ids(1000, 1000);
        CHECK(setuid(0) < 0 && errno == EPERM && setgid(0) < 0 && errno == EPERM);
        CHECK(kill(getppid(), 0) < 0 && errno == EPERM);
        CHECK(account_auth_root_switch(path, "root", &profile) < 0 && errno == EPERM);
        _exit(0);
    }
    wait_child(child);
    account_profile_free(profile);
    observed("all-user-identities-and-cross-process-denial");
    CHECK(account_auth_root_switch(path, "bob", &profile) == 0 && profile);
    CHECK(chmod(argv[2], 04755) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(account_profile_enter(profile, 0) == 0);
        execl(argv[2], argv[2], "--privileged-control", (char*)0);
        _exit(99);
    }
    wait_child(child);
    observed("same-executable-setuid-control-is-effective");
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setenv("LD_PRELOAD", "/fixture-poison", 1) == 0 &&
              setenv("LD_LIBRARY_PATH", "/fixture-poison", 1) == 0);
        CHECK(setenv("EVIL_FIXTURE_ENV", "discard", 1) == 0);
        CHECK(account_profile_enter(profile, 1) == 0);
        CHECK(account_profile_environment(profile, "vt100") == 0 && chdir(profile->home) == 0);
        umask(077);
        execl(argv[2], argv[2], "--service-observe", bob_home, private_file, (char*)0);
        _exit(99);
    }
    wait_child(child);
    CHECK(chmod(argv[2], 0755) == 0);
    account_profile_free(profile);
    observed("service-exec-no-new-privileges-clean-environment-cwd-umask-and-file-denial");
    printf("ACCOUNT_AUTH_PASS observations=%u\n", observations);
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/database.h"
#include "../../accounts/store.h"
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
            fprintf(stderr, "ACCOUNT_DATABASE_FAIL line=%d errno=%d\n", __LINE__, errno);          \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;

static void observed(const char* name) {
    printf("ACCOUNT_DATABASE_OBSERVATION case=%s\n", name);
    observations++;
}

static struct account_database* begin(const char* path, int provision) {
    struct account_database* result = NULL;
    CHECK(account_database_begin(path, provision, &result) == 0 && result);
    return result;
}

static void group(struct account_database* db, const char* name, gid_t gid) {
    struct account_group value = {name, gid, NULL, 0};
    CHECK(account_database_put_group(db, NULL, &value) == 0);
}

static void user(struct account_database* db, const char* name, uid_t uid, gid_t gid) {
    struct account_user value = {name, "!", "Ordinary account",     "/home/user", "/bin/sh",
                                 uid,  gid, {-1, 0, -1, -1, -1, -1}};
    CHECK(account_database_put_user(db, NULL, &value) == 0);
}

static void libc_records(const char* path) {
    char name[4096];
    CHECK(snprintf(name, sizeof(name), "%s/current/passwd", path) < (int)sizeof(name));
    FILE* file = fopen(name, "r");
    CHECK(file);
    struct passwd* pw = fgetpwent(file);
    CHECK(pw && !strcmp(pw->pw_name, "root") && pw->pw_uid == 0 && pw->pw_gid == 0);
    pw = fgetpwent(file);
    CHECK(pw && !strcmp(pw->pw_name, "carol") && pw->pw_uid == UINT32_MAX - 1 &&
          pw->pw_gid == 4000000000u);
    CHECK(!fgetpwent(file) && fclose(file) == 0);
    CHECK(snprintf(name, sizeof(name), "%s/current/group", path) < (int)sizeof(name));
    file = fopen(name, "r");
    CHECK(file);
    struct group* gr;
    int found = 0;
    while ((gr = fgetgrent(file)))
        if (!strcmp(gr->gr_name, "wheel")) {
            CHECK(gr->gr_gid == 28 && gr->gr_mem[0] && !strcmp(gr->gr_mem[0], "carol") &&
                  !gr->gr_mem[1]);
            found++;
        }
    CHECK(found == 1 && fclose(file) == 0);
    CHECK(snprintf(name, sizeof(name), "%s/current/shadow", path) < (int)sizeof(name));
    file = fopen(name, "r");
    CHECK(file);
    struct spwd* sp = fgetspent(file);
    CHECK(sp && !strcmp(sp->sp_namp, "root") && !strcmp(sp->sp_pwdp, "!"));
    sp = fgetspent(file);
    CHECK(sp && !strcmp(sp->sp_namp, "carol") && !strcmp(sp->sp_pwdp, "!") && sp->sp_lstchg == -1 &&
          sp->sp_min == 0);
    CHECK(!fgetspent(file) && fclose(file) == 0);
    observed("real-libc-record-parsers");
}

static void malformed(const char* base, unsigned index, const char* passwd, const char* groups,
                      const char* shadow) {
    char path[4096];
    CHECK(snprintf(path, sizeof(path), "%s/damaged-%u", base, index) < (int)sizeof(path));
    struct account_store* store = NULL;
    CHECK(account_store_begin(path, 1, &store) == 0);
    struct account_content files[ACCOUNT_FILE_COUNT] = {
        {passwd, strlen(passwd)}, {groups, strlen(groups)}, {shadow, strlen(shadow)}};
    int published = 0;
    CHECK(account_store_commit(store, files, &published) == 0 && published == 1);
    account_store_end(store);
    struct account_database* db = NULL;
    errno = ENOMEM;
    CHECK(account_database_begin(path, 0, &db) < 0 && errno == EUCLEAN && !db);
    observed("malformed-committed-records-denied");
}

int main(int argc, char** argv) {
    CHECK(argc == 2 && !geteuid() && !getegid());
    CHECK(mkdir(argv[1], 0755) == 0 || errno == EEXIST);
    CHECK(chmod(argv[1], 0755) == 0);
    char path[4096];
    CHECK(snprintf(path, sizeof(path), "%s/db", argv[1]) < (int)sizeof(path));
    uint32_t id;
    CHECK(account_id_parse("4294967294", &id) == 0 && id == UINT32_MAX - 1);
    for (const char** value = (const char*[]){"", "-1", "+1", " 1", "0x10", "1x", "4294967295",
                                              "9999999999999999999", NULL};
         *value; value++)
        CHECK(account_id_parse(*value, &id) < 0);
    CHECK(account_name_valid("ordinary-user_1") && !account_name_valid("-option") &&
          !account_name_valid("1user") && !account_name_valid("bad:name") &&
          !account_name_valid("../user"));
    observed("name-and-full-width-id-validation");
    struct account_database* db = begin(path, 1);
    CHECK(account_database_fresh(db));
    CHECK(account_database_uid(db, 0) && !strcmp(account_database_uid(db, 0)->password, "!"));
    group(db, "users", 1000);
    group(db, "bob", 1001);
    group(db, "sudo", 27);
    user(db, "alice", 1000, 1000);
    user(db, "bob", 1001, 1001);
    CHECK(account_database_member(db, "sudo", "alice", 1) == 0);
    observed("create-users-groups-and-memberships");
    struct account_user duplicate = *account_database_user(db, "alice");
    duplicate.name = "other";
    CHECK(account_database_put_user(db, NULL, &duplicate) < 0 && errno == EEXIST);
    duplicate.uid = 2000;
    duplicate.name = "alice";
    CHECK(account_database_put_user(db, NULL, &duplicate) < 0 && errno == EEXIST);
    duplicate.name = "other";
    duplicate.gid = 2000;
    CHECK(account_database_put_user(db, NULL, &duplicate) < 0 && errno == ENOENT);
    struct account_group duplicate_group = {"other", 27, NULL, 0};
    CHECK(account_database_put_group(db, NULL, &duplicate_group) < 0 && errno == EEXIST);
    observed("duplicate-and-dangling-ids-denied");
    CHECK(account_database_remove_group(db, "users") < 0 && errno == EBUSY);
    CHECK(account_database_remove_user(db, "root") < 0 && errno == EPERM);
    CHECK(account_database_remove_group(db, "root") < 0 && errno == EPERM);
    observed("primary-group-and-root-protection");
    struct account_user updated = *account_database_user(db, "alice");
    updated.name = "carol";
    updated.uid = UINT32_MAX - 1;
    CHECK(account_database_put_user(db, "alice", &updated) == 0);
    CHECK(!account_database_user(db, "alice") &&
          account_database_group(db, "sudo")->members[0] == UINT32_MAX - 1);
    struct account_group changed = *account_database_group(db, "users");
    changed.gid = 4000000000u;
    CHECK(account_database_put_group(db, "users", &changed) == 0);
    CHECK(account_database_user(db, "carol")->gid == 4000000000u);
    changed = *account_database_group(db, "sudo");
    changed.name = "wheel";
    changed.gid = 28;
    CHECK(account_database_put_group(db, "sudo", &changed) == 0 &&
          !account_database_group(db, "sudo"));
    observed("rename-and-id-update-keeps-relations");
    size_t count = 0;
    CHECK(account_database_groups(db, UINT32_MAX - 1, NULL, 0, &count) < 0 && errno == ERANGE &&
          count == 2);
    gid_t gids[2];
    CHECK(account_database_groups(db, UINT32_MAX - 1, gids, 2, &count) == 0 && count == 2 &&
          gids[0] == 4000000000u && gids[1] == 28);
    observed("supplementary-groups-and-query-capacity");
    CHECK(account_database_remove_user(db, "bob") == 0 &&
          account_database_remove_group(db, "bob") == 0);
    int published = 0;
    CHECK(account_database_commit(db, &published) == 0 && published == 1);
    account_database_end(db);
    db = begin(path, 0);
    CHECK(!account_database_fresh(db) && account_database_uid(db, UINT32_MAX - 1) &&
          !account_database_user(db, "bob"));
    CHECK(account_database_group(db, "wheel")->members[0] == UINT32_MAX - 1);
    account_database_end(db);
    observed("reopen-complete-committed-generation");
    libc_records(path);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(setgroups(0, NULL) == 0 && setgid(1000) == 0 && setuid(1000) == 0);
        CHECK(account_database_begin(path, 1, &db) < 0 && errno == EPERM && !db);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    observed("ordinary-administration-denied");
    const char *pw = "root:x:0:0:root:/root:/bin/sh\n", *gr = "root:x:0:\n",
               *sp = "root:!:::::::\n";
    malformed(argv[1], 0, "root:x:0:0:root:/root:/bin/sh\nroot:x:1:0::/:/bin/sh\n", gr, sp);
    malformed(argv[1], 1, "root:x:0:0:root:/root:/bin/sh\nother:x:0:0::/:/bin/sh\n", gr, sp);
    malformed(argv[1], 2, "root:x:0:1:root:/root:/bin/sh\n", gr, sp);
    malformed(argv[1], 3, pw, "root:x:0:missing\n", sp);
    malformed(argv[1], 4, pw, "root:x:0:root,root\n", sp);
    malformed(argv[1], 5, pw, "root:x:0:\nother:x:0:\n", sp);
    malformed(argv[1], 6, pw, gr, "root:!:::::::\nroot:!:::::::\n");
    malformed(argv[1], 7, pw, gr, "missing:!:::::::\n");
    malformed(argv[1], 8, pw, gr, "root:!:999999999999999999999999:0:::::\n");
    malformed(argv[1], 9, "root:x:4294967295:0:root:/root:/bin/sh\n", gr, sp);
    malformed(argv[1], 10, "root:x:0:0:root:../root:/bin/sh\n", gr, sp);
    malformed(argv[1], 11, pw, gr, "root:!:::::::reserved\n");
    printf("ACCOUNT_DATABASE_PASS observations=%u\n", observations);
    return 0;
}

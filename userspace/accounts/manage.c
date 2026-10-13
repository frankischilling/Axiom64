// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "database.h"
#include "guard.h"
#include "password.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void usage(void) {
    fputs("usage: accountctl [--database PATH] [--records PATH] COMMAND ARGUMENTS\n"
          "  bootstrap NAME HOME SHELL --password-fd FD\n"
          "  group-add NAME GID | group-delete NAME | group-rename NAME NEW\n"
          "  user-add NAME UID GROUP HOME SHELL | user-delete NAME\n"
          "  user-rename NAME NEW | user-shell NAME SHELL | user-home NAME HOME\n"
          "  member-add GROUP USER | member-delete GROUP USER\n"
          "  password NAME --password-fd FD | lock NAME | unlock NAME\n"
          "  show NAME\n",
          stderr);
}

static int failed(int error) {
    errno = error;
    return -1;
}

static int password_fd(const char* argument, char output[ACCOUNT_PASSWORD_HASH_SIZE]) {
    uint32_t descriptor;
    if (account_id_parse(argument, &descriptor) < 0 || descriptor > 2147483647u)
        return failed(EINVAL);
    char secret[ACCOUNT_PASSWORD_MAX + 1] = {0};
    size_t used = 0;
    int error = 0;
    for (;;) {
        char byte;
        ssize_t count = read((int)descriptor, &byte, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            error = errno;
            break;
        }
        if (!count || byte == '\n')
            break;
        if (!byte || byte == '\r' || used == ACCOUNT_PASSWORD_MAX) {
            error = EINVAL;
            break;
        }
        secret[used++] = byte;
    }
    if (!error && !used)
        error = EINVAL;
    if (!error && account_password_hash(secret, output) < 0)
        error = errno;
    account_password_clear(secret, sizeof(secret));
    return error ? failed(error) : 0;
}

static int changed_password(struct account_database* db, const char* name, const char* fd) {
    const struct account_user* found = account_database_user(db, name);
    if (!found)
        return failed(ENOENT);
    char encoded[ACCOUNT_PASSWORD_HASH_SIZE] = {0};
    if (password_fd(fd, encoded) < 0)
        return -1;
    time_t now = time(NULL);
    int error = now < 0 ? EIO : 0;
    struct account_user changed = *found;
    changed.password = encoded;
    changed.age[0] = (int64_t)now / 86400;
    if (!error && account_database_put_user(db, name, &changed) < 0)
        error = errno;
    account_password_clear(encoded, sizeof(encoded));
    return error ? failed(error) : 0;
}

static const struct account_group* selected_group(struct account_database* db, const char* name) {
    const struct account_group* result = account_database_group(db, name);
    if (result)
        return result;
    uint32_t id;
    return account_id_parse(name, &id) < 0 ? NULL : account_database_gid(db, id);
}

static int operation(struct account_database* db, int argc, char** argv, int* create_home) {
    if (argc < 1)
        return failed(EINVAL);
    const char* command = argv[0];
    if (!strcmp(command, "bootstrap") && argc == 6 && !strcmp(argv[4], "--password-fd")) {
        if (!account_database_fresh(db))
            return failed(EEXIST);
        struct account_group group = {argv[1], 1000, NULL, 0};
        if (account_database_put_group(db, NULL, &group) < 0)
            return -1;
        group = (struct account_group){"sudo", 27, NULL, 0};
        if (account_database_put_group(db, NULL, &group) < 0)
            return -1;
        struct account_user user = {argv[1], "!",  "Administrator",        argv[2], argv[3],
                                    1000,    1000, {-1, 0, -1, -1, -1, -1}};
        if (account_database_put_user(db, NULL, &user) < 0 ||
            changed_password(db, argv[1], argv[5]) < 0 ||
            account_database_member(db, "sudo", argv[1], 1) < 0)
            return -1;
        *create_home = 1;
        return 0;
    }
    if (!strcmp(command, "group-add") && argc == 3) {
        uint32_t id;
        if (account_id_parse(argv[2], &id) < 0)
            return -1;
        struct account_group group = {argv[1], id, NULL, 0};
        return account_database_put_group(db, NULL, &group);
    }
    if (!strcmp(command, "group-delete") && argc == 2)
        return account_database_remove_group(db, argv[1]);
    if (!strcmp(command, "group-rename") && argc == 3) {
        const struct account_group* found = account_database_group(db, argv[1]);
        if (!found)
            return failed(ENOENT);
        struct account_group group = *found;
        group.name = argv[2];
        return account_database_put_group(db, argv[1], &group);
    }
    if (!strcmp(command, "user-add") && argc == 6) {
        uint32_t id;
        const struct account_group* group = selected_group(db, argv[3]);
        if (!group)
            return failed(ENOENT);
        if (account_id_parse(argv[2], &id) < 0)
            return -1;
        struct account_user user = {argv[1], "!", "",         argv[4],
                                    argv[5], id,  group->gid, {-1, 0, -1, -1, -1, -1}};
        if (account_database_put_user(db, NULL, &user) < 0)
            return -1;
        *create_home = 1;
        return 0;
    }
    if (!strcmp(command, "user-delete") && argc == 2)
        return account_database_remove_user(db, argv[1]);
    if ((!strcmp(command, "member-add") || !strcmp(command, "member-delete")) && argc == 3)
        return account_database_member(db, argv[1], argv[2], !strcmp(command, "member-add"));
    if (!strcmp(command, "password") && argc == 4 && !strcmp(argv[2], "--password-fd"))
        return changed_password(db, argv[1], argv[3]);
    if (argc == 2 && (!strcmp(command, "lock") || !strcmp(command, "unlock"))) {
        const struct account_user* found = account_database_user(db, argv[1]);
        if (!found)
            return failed(ENOENT);
        struct account_user user = *found;
        char encoded[ACCOUNT_PASSWORD_HASH_SIZE];
        if (!strcmp(command, "lock")) {
            if (*user.password == '!')
                return 0;
            size_t size = strlen(user.password);
            if (size >= sizeof(encoded) - 1)
                return failed(EOVERFLOW);
            encoded[0] = '!';
            memcpy(encoded + 1, user.password, size + 1);
            user.password = encoded;
        } else {
            if (*user.password != '!')
                return 0;
            if (!user.password[1] || user.password[1] == '!' || user.password[1] == '*')
                return failed(EACCES);
            user.password++;
        }
        int result = account_database_put_user(db, argv[1], &user);
        int error = errno;
        account_password_clear(encoded, sizeof(encoded));
        return result < 0 ? failed(error) : 0;
    }
    if ((!strcmp(command, "user-rename") || !strcmp(command, "user-home") ||
         !strcmp(command, "user-shell")) &&
        argc == 3) {
        const struct account_user* found = account_database_user(db, argv[1]);
        if (!found)
            return failed(ENOENT);
        struct account_user user = *found;
        if (!strcmp(command, "user-rename"))
            user.name = argv[2];
        else if (!strcmp(command, "user-home"))
            user.home = argv[2];
        else
            user.shell = argv[2];
        return account_database_put_user(db, argv[1], &user);
    }
    return failed(EINVAL);
}

static enum account_login_kind event(const char* command) {
    static const struct {
        const char* name;
        enum account_login_kind kind;
    } commands[] = {{"bootstrap", ACCOUNT_LOGIN_BOOTSTRAP},
                    {"user-add", ACCOUNT_LOGIN_USER_ADD},
                    {"user-delete", ACCOUNT_LOGIN_USER_DELETE},
                    {"user-rename", ACCOUNT_LOGIN_USER_RENAME},
                    {"user-home", ACCOUNT_LOGIN_USER_HOME},
                    {"user-shell", ACCOUNT_LOGIN_USER_SHELL},
                    {"group-add", ACCOUNT_LOGIN_GROUP_ADD},
                    {"group-delete", ACCOUNT_LOGIN_GROUP_DELETE},
                    {"group-rename", ACCOUNT_LOGIN_GROUP_RENAME},
                    {"member-add", ACCOUNT_LOGIN_MEMBER_ADD},
                    {"member-delete", ACCOUNT_LOGIN_MEMBER_DELETE},
                    {"password", ACCOUNT_LOGIN_PASSWORD},
                    {"lock", ACCOUNT_LOGIN_LOCK},
                    {"unlock", ACCOUNT_LOGIN_UNLOCK}};

    for (size_t i = 0; i < sizeof(commands) / sizeof(*commands); i++)
        if (!strcmp(command, commands[i].name))
            return commands[i].kind;
    return 0;
}

static int guard(struct account_database* db, const struct account_logbook* book, int argc,
                 char** argv) {
    const char* command = argv[0];
    if ((!strcmp(command, "user-delete") && argc == 2) ||
        ((!strcmp(command, "user-rename") || !strcmp(command, "user-home")) && argc == 3))
        return account_guard_user(db, book, argv[1]);
    if ((!strcmp(command, "group-delete") && argc == 2) ||
        (!strcmp(command, "group-rename") && argc == 3))
        return account_guard_group(db, book, argv[1]);
    uint32_t id;
    if (!strcmp(command, "user-add") && argc == 6) {
        if (account_id_parse(argv[2], &id) < 0)
            return -1;
        return account_guard_new_ids(book, id, (gid_t)-1);
    }
    if (!strcmp(command, "group-add") && argc == 3) {
        if (account_id_parse(argv[2], &id) < 0)
            return -1;
        return account_guard_new_ids(book, (uid_t)-1, id);
    }
    if (!strcmp(command, "bootstrap") && argc == 6) {
        if (account_guard_new_ids(book, 1000, 1000) < 0)
            return -1;
        return account_guard_new_ids(book, (uid_t)-1, 27);
    }
    return 0;
}

int main(int argc, char** argv) {
    if (getuid() || geteuid() || getegid()) {
        fputs("accountctl: root administration is required\n", stderr);
        return 1;
    }
    const char* path = "/etc/axiom64/accounts";
    const char* records = "/var/log/axiom64/login";
    int first = 1;
    while (argc > first + 2 &&
           (!strcmp(argv[first], "--database") || !strcmp(argv[first], "--records"))) {
        if (!strcmp(argv[first], "--database"))
            path = argv[first + 1];
        else
            records = argv[first + 1];
        first += 2;
    }
    if (argc <= first) {
        usage();
        return 2;
    }
    int bootstrap = !strcmp(argv[first], "bootstrap");
    struct account_database* db = NULL;
    if (account_database_begin(path, bootstrap, &db) < 0) {
        perror("accountctl: open database");
        return 1;
    }
    int recovery_error = account_database_recovery_error(db);
    if (recovery_error)
        fprintf(stderr, "accountctl: pending home recovery: %s; updates are blocked\n",
                strerror(recovery_error));
    if (!strcmp(argv[first], "show") && argc == first + 2) {
        const struct account_user* user = account_database_user(db, argv[first + 1]);
        int result = user ? 0 : 1;
        if (user)
            printf("name=%s uid=%u gid=%u home=%s shell=%s password=%s\n", user->name,
                   (unsigned)user->uid, (unsigned)user->gid, user->home, user->shell,
                   !*user->password || *user->password == '!' || *user->password == '*' ? "disabled"
                                                                                        : "set");
        else
            fputs("accountctl: account does not exist\n", stderr);
        account_database_end(db);
        return result;
    }
    int create_home = 0, published = 0;
    struct account_logbook* book = NULL;
    enum account_login_kind kind = event(argv[first]);
    const char* target =
        argc > first + 1 && account_name_valid(argv[first + 1]) ? argv[first + 1] : NULL;
    int error = !kind ? EINVAL : account_logbook_open(records, 1, &book) < 0 ? errno : 0;
    int intended = 0;
    if (!error) {
        if (account_logbook_audit(book, kind, "root", 0, target, "", EINPROGRESS) < 0)
            error = errno;
        else
            intended = 1;
    }
    if (!error && (guard(db, book, argc - first, argv + first) < 0 ||
                   operation(db, argc - first, argv + first, &create_home) < 0))
        error = errno;
    if (!error && (create_home ? account_database_commit_home(db, argv[first + 1], &published)
                               : account_database_commit(db, &published)) < 0)
        error = errno;
    if (error && published)
        fputs("accountctl: the complete update is visible; durability or cleanup failed\n", stderr);
    if (intended && account_logbook_audit(book, kind, "root", 0, target, "", error) < 0 && !error)
        error = errno;
    account_logbook_close(book);
    account_database_end(db);
    if (error) {
        if (error == EINVAL)
            usage();
        errno = error;
        perror("accountctl: update");
        return error == EINVAL ? 2 : 1;
    }
    return 0;
}

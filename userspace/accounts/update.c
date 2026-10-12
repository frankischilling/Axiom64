// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "update.h"
#include "database.h"
#include "home.h"
#include "logbook.h"
#include "password.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int failed(int error) {
    errno = error;
    return -1;
}

static int same_revision(const struct account_database* db, const struct account_profile* profile) {
    const char* revision = account_database_revision(db);
    const struct account_user* user = profile ? account_database_uid(db, profile->uid) : NULL;
    return revision && profile && !strcmp(revision, profile->revision) && user &&
           !strcmp(user->name, profile->name);
}

int account_password_update(const char* database, const char* records,
                            const struct account_profile* target,
                            const struct account_profile* authorization, const char* password,
                            int* published) {
    if (!target || !password || !published)
        return failed(EINVAL);
    *published = 0;
    if (!authorization && getuid())
        return failed(EPERM);
    if (authorization && authorization->uid != target->uid)
        return failed(EACCES);
    char encoded[ACCOUNT_PASSWORD_HASH_SIZE] = {0};
    if (account_password_hash(password, encoded) < 0)
        return -1;
    struct account_database* db = NULL;
    struct account_logbook* book = NULL;
    int error = account_database_begin(database, 0, &db) < 0 ? errno : 0;
    if (!error &&
        (!same_revision(db, target) || (authorization && !same_revision(db, authorization))))
        error = ESTALE;
    time_t now = time(NULL);
    int64_t today = now < 0 ? -1 : (int64_t)now / 86400;
    if (!error && today < 0)
        error = EIO;
    const struct account_user* user = !error ? account_database_uid(db, target->uid) : NULL;
    if (!error && authorization && !authorization->password_change_required && user->age[0] >= 0 &&
        user->age[1] > 0 && (today < user->age[0] || today - user->age[0] < user->age[1]))
        error = EACCES;
    if (!error && account_logbook_open(records, 1, &book) < 0)
        error = errno;
    const char* actor = authorization ? authorization->name : "root";
    uid_t actor_uid = authorization ? authorization->uid : 0;
    int intended = 0;
    if (!error) {
        if (account_logbook_audit(book, ACCOUNT_LOGIN_PASSWORD, actor, actor_uid, target->name, "",
                                  EINPROGRESS) < 0)
            error = errno;
        else
            intended = 1;
    }
    if (!error) {
        struct account_user changed = *user;
        changed.password = encoded;
        changed.age[0] = today;
        if (account_database_put_user(db, target->name, &changed) < 0 ||
            account_database_commit(db, published) < 0)
            error = errno;
    }
    if (intended &&
        account_logbook_audit(book, ACCOUNT_LOGIN_PASSWORD, actor, actor_uid, target->name, "",
                              error) < 0 &&
        !error)
        error = errno;
    account_logbook_close(book);
    account_database_end(db);
    account_password_clear(encoded, sizeof(encoded));
    return error ? failed(error) : 0;
}

int account_bootstrap(const char* database, const char* records, const char* name, const char* home,
                      const char* shell, const char* password, int* published) {
    if (!name || !home || !shell || !password || !published || !account_name_valid(name))
        return failed(EINVAL);
    *published = 0;
    if (getuid() || geteuid() || getegid())
        return failed(EPERM);
    char encoded[ACCOUNT_PASSWORD_HASH_SIZE] = {0};
    if (account_password_hash(password, encoded) < 0)
        return -1;
    struct account_database* db = NULL;
    struct account_logbook* book = NULL;
    int error = account_database_begin(database, 1, &db) < 0 ? errno : 0;
    if (!error && !account_database_fresh(db))
        error = EEXIST;
    time_t now = time(NULL);
    if (!error && now < 0)
        error = EIO;
    struct account_group primary = {name, 1000, NULL, 0}, sudo = {"sudo", 27, NULL, 0};
    struct account_user user = {name,
                                encoded,
                                "Administrator",
                                home,
                                shell,
                                1000,
                                1000,
                                {(int64_t)now / 86400, 0, -1, -1, -1, -1}};
    if (!error && (account_database_put_group(db, NULL, &primary) < 0 ||
                   account_database_put_group(db, NULL, &sudo) < 0 ||
                   account_database_put_user(db, NULL, &user) < 0 ||
                   account_database_member(db, "sudo", name, 1) < 0))
        error = errno;
    if (!error && account_logbook_open(records, 1, &book) < 0)
        error = errno;
    int intended = 0, created = 0;
    if (!error) {
        if (account_logbook_audit(book, ACCOUNT_LOGIN_ADMIN, "root", 0, name, "", EINPROGRESS) < 0)
            error = errno;
        else
            intended = 1;
    }
    if (!error && (account_home_create(home, 1000, 1000, &created) < 0 ||
                   account_database_commit(db, published) < 0))
        error = errno;
    if (error && created && !*published && account_home_rollback(home, 1000, 1000) < 0)
        error = errno;
    if (intended &&
        account_logbook_audit(book, ACCOUNT_LOGIN_ADMIN, "root", 0, name, "", error) < 0 && !error)
        error = errno;
    account_logbook_close(book);
    account_database_end(db);
    account_password_clear(encoded, sizeof(encoded));
    return error ? failed(error) : 0;
}

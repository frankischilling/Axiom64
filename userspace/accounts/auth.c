// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "auth.h"
#include "database.h"
#include "password.h"
#include <errno.h>
#include <grp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int failed(int error) {
    errno = error;
    return -1;
}

void account_profile_free(struct account_profile* profile) {
    if (!profile)
        return;
    free(profile->name);
    free(profile->home);
    free(profile->shell);
    free(profile->groups);
    explicit_bzero(profile, sizeof(*profile));
    free(profile);
}

static int profile_create(struct account_database* db, const struct account_user* user,
                          struct account_profile** output) {
    struct account_profile* profile = calloc(1, sizeof(*profile));
    if (!profile)
        return -1;
    profile->name = strdup(user->name);
    profile->home = strdup(user->home);
    profile->shell = strdup(*user->shell ? user->shell : "/bin/sh");
    profile->uid = user->uid;
    profile->gid = user->gid;
    size_t count = 0;
    int error = 0;
    if (account_database_groups(db, user->uid, NULL, 0, &count) == 0 || errno != ERANGE)
        error = EINVAL;
    if (!error && count > 65536)
        error = E2BIG;
    if (!error) {
        profile->groups = malloc(count * sizeof(*profile->groups));
        if (!profile->groups)
            error = ENOMEM;
    }
    if (!error &&
        account_database_groups(db, user->uid, profile->groups, count, &profile->group_count) < 0)
        error = errno;
    if (!profile->name || !profile->home || !profile->shell)
        error = ENOMEM;
    if (error) {
        account_profile_free(profile);
        return failed(error);
    }
    *output = profile;
    return 0;
}

static int status(const struct account_user* user) {
    time_t now = time(NULL);
    if (now < 0)
        return failed(EIO);
    int64_t today = (int64_t)now / 86400;
    if (user->age[5] >= 0 && today >= user->age[5])
        return ACCOUNT_AUTH_DENIED;
    if (!user->age[0])
        return ACCOUNT_AUTH_CHANGE_REQUIRED;
    if (user->age[0] < 0 || today < user->age[0] || user->age[2] < 0)
        return ACCOUNT_AUTH_ACCEPTED;
    int64_t elapsed = today - user->age[0];
    if (user->age[4] >= 0) {
        int64_t limit =
            user->age[2] <= INT64_MAX - user->age[4] ? user->age[2] + user->age[4] : INT64_MAX;
        if (elapsed >= limit)
            return ACCOUNT_AUTH_DENIED;
    }
    return elapsed >= user->age[2] ? ACCOUNT_AUTH_CHANGE_REQUIRED : ACCOUNT_AUTH_ACCEPTED;
}

int account_auth_password(const char* path, const char* name, const char* password,
                          int require_sudo, struct account_profile** output) {
    if (!output || !name || !password || (require_sudo != 0 && require_sudo != 1))
        return failed(EINVAL);
    *output = NULL;
    struct account_database* db = NULL;
    if (account_database_begin(path, 0, &db) < 0)
        return -1;
    const struct account_user* user = account_database_user(db, name);
    int result = ACCOUNT_AUTH_DENIED, error = 0;
    if (!user)
        goto done;
    if (require_sudo) {
        const struct account_group* group = account_database_group(db, "sudo");
        int member = group && user->gid == group->gid;
        if (group)
            for (size_t i = 0; i < group->member_count; i++)
                member |= group->members[i] == user->uid;
        if (!member)
            goto done;
    }
    int verified = account_password_verify(password, user->password);
    if (verified < 0) {
        error = errno;
        goto done;
    }
    if (!verified)
        goto done;
    result = status(user);
    if (result < 0)
        error = errno;
    else if (result != ACCOUNT_AUTH_DENIED) {
        if (profile_create(db, user, output) < 0)
            error = errno;
        else
            (*output)->password_change_required = result == ACCOUNT_AUTH_CHANGE_REQUIRED;
    }
done:
    account_database_end(db);
    return error ? failed(error) : result;
}

int account_auth_root_switch(const char* path, const char* name, struct account_profile** output) {
    if (!output || !name)
        return failed(EINVAL);
    *output = NULL;
    if (getuid() || geteuid() || getegid())
        return failed(EPERM);
    struct account_database* db = NULL;
    if (account_database_begin(path, 0, &db) < 0)
        return -1;
    const struct account_user* user = account_database_user(db, name);
    int error = !user ? ENOENT : profile_create(db, user, output) < 0 ? errno : 0;
    account_database_end(db);
    return error ? failed(error) : 0;
}

struct capability_header {
    uint32_t version;
    int32_t pid;
};

struct capability_data {
    uint32_t effective, permitted, inheritable;
};

_Static_assert(sizeof(struct capability_header) == 8 && sizeof(struct capability_data) == 12,
               "Linux v3 capability wire layout");

int account_profile_enter(const struct account_profile* profile, int service) {
    if (!profile || profile->uid == (uid_t)-1 || profile->gid == (gid_t)-1 ||
        profile->group_count > 65536 || (profile->group_count && !profile->groups) ||
        (service != 0 && service != 1) || (service && !profile->uid))
        return failed(EINVAL);
    if (profile->password_change_required)
        return failed(EACCES);
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) < 0 ||
        setgroups(profile->group_count, profile->groups) < 0 ||
        setresgid(profile->gid, profile->gid, profile->gid) < 0 ||
        setresuid(profile->uid, profile->uid, profile->uid) < 0)
        return -1;
    if ((uid_t)setfsuid((uid_t)-1) != profile->uid || (gid_t)setfsgid((gid_t)-1) != profile->gid)
        return failed(EPERM);
    uid_t real, effective, saved;
    gid_t gr, ge, gs;
    if (getresuid(&real, &effective, &saved) < 0 || getresgid(&gr, &ge, &gs) < 0)
        return -1;
    if (real != profile->uid || effective != profile->uid || saved != profile->uid ||
        gr != profile->gid || ge != profile->gid || gs != profile->gid)
        return failed(EPERM);
    if (profile->uid) {
        struct capability_header header = {0x20080522, 0};
        struct capability_data data[2] = {{0}, {0}};
        if (syscall(SYS_capset, &header, data) < 0 ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
            return -1;
        if (syscall(SYS_capget, &header, data) < 0)
            return -1;
        for (unsigned i = 0; i < 2; i++)
            if (data[i].effective || data[i].permitted || data[i].inheritable)
                return failed(EPERM);
    }
    if (service && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return 0;
}

int account_profile_environment(const struct account_profile* profile, const char* terminal) {
    if (!profile || !profile->name || !profile->home || !profile->shell)
        return failed(EINVAL);
    if (terminal) {
        size_t size = strnlen(terminal, 128);
        if (!size || size == 128)
            return failed(EINVAL);
        for (size_t i = 0; i < size; i++)
            if (!((terminal[i] >= 'a' && terminal[i] <= 'z') ||
                  (terminal[i] >= 'A' && terminal[i] <= 'Z') ||
                  (terminal[i] >= '0' && terminal[i] <= '9') || terminal[i] == '-' ||
                  terminal[i] == '_'))
                return failed(EINVAL);
    }
    if (clearenv() < 0 || setenv("HOME", profile->home, 1) < 0 ||
        setenv("USER", profile->name, 1) < 0 || setenv("LOGNAME", profile->name, 1) < 0 ||
        setenv("SHELL", profile->shell, 1) < 0 ||
        setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1) < 0 || setenv("LANG", "C.UTF-8", 1) < 0 ||
        (terminal && setenv("TERM", terminal, 1) < 0))
        return -1;
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
#include "guard.h"
#include "busy.h"
#include <errno.h>

static int failed(int error) {
    errno = error;
    return -1;
}

int account_guard_new_ids(const struct account_logbook* book, uid_t uid, gid_t gid) {
    if (uid != (uid_t)-1) {
        int active = account_logbook_active(book, uid);
        if (active < 0)
            return -1;
        if (active)
            return failed(EBUSY);
    }
    int active = account_process_busy(uid, gid);
    return active < 0 ? -1 : active ? failed(EBUSY) : 0;
}

int account_guard_user(const struct account_database* db, const struct account_logbook* book,
                       const char* name) {
    const struct account_user* user = account_database_user(db, name);
    if (!user)
        return failed(ENOENT);
    return account_guard_new_ids(book, user->uid, (gid_t)-1);
}

int account_guard_group(const struct account_database* db, const struct account_logbook* book,
                        const char* name) {
    const struct account_group* group = account_database_group(db, name);
    if (!group)
        return failed(ENOENT);
    int active = account_process_busy((uid_t)-1, group->gid);
    if (active < 0)
        return -1;
    if (active)
        return failed(EBUSY);
    for (size_t index = 0;; index++) {
        const struct account_user* user = account_database_user_at(db, index);
        if (!user)
            break;
        int member = user->gid == group->gid;
        for (size_t i = 0; i < group->member_count; i++)
            member |= group->members[i] == user->uid;
        if (member) {
            active = account_logbook_active(book, user->uid);
            if (active < 0)
                return -1;
            if (active)
                return failed(EBUSY);
        }
    }
    return 0;
}

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/guard.c
 * @brief   Account storage locking.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Acquires and releases the advisory locks that protect account database
 * operations.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
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

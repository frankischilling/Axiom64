// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/recorded.c
 * @brief   Recorded session execution.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Wraps authenticated session startup and exit with accounting record updates.
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
#define _GNU_SOURCE
#include "recorded.h"
#include "database.h"
#include <errno.h>
#include <string.h>

static int failed(int error) {
    errno = error;
    return -1;
}

int account_recorded_deny(const char* records, const char* name, const char* terminal) {
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

int account_recorded_begin(void* opaque, pid_t child, const char* terminal) {
    struct account_recorded_session* context = opaque;
    if (!context || !context->target || context->lease)
        return failed(EINVAL);
    struct account_database* db = NULL;
    if (account_database_begin(context->database, 0, &db) < 0)
        return -1;
    const char* revision = account_database_revision(db);
    int error = !revision || strcmp(revision, context->target->revision) ? ESTALE : 0;
    if (!error && context->authorization && strcmp(revision, context->authorization->revision))
        error = ESTALE;
    const struct account_user* target = account_database_uid(db, context->target->uid);
    if (!error && (!target || strcmp(target->name, context->target->name)))
        error = ESTALE;
    const struct account_user* actor = account_database_uid(db, context->actor);
    if (!error && !actor)
        error = ENOENT;
    if (!error && context->operation == ACCOUNT_LOGIN_SUDO && context->actor) {
        const struct account_group* group = account_database_group(db, "sudo");
        int member = group && actor->gid == group->gid;
        if (group)
            for (size_t i = 0; i < group->member_count; i++)
                member |= group->members[i] == actor->uid;
        if (!member || !context->authorization || context->authorization->uid != actor->uid)
            error = EACCES;
    }
    struct account_logbook* book = NULL;
    if (!error && account_logbook_open(context->records, 1, &book) < 0)
        error = errno;
    if (!error && context->operation != ACCOUNT_LOGIN_START &&
        account_logbook_audit(book, context->operation, actor->name, actor->uid, target->name,
                              terminal, 0) < 0)
        error = errno;
    if (!error &&
        account_logbook_begin(book, context->target, child, terminal, &context->lease) < 0)
        error = errno;
    account_logbook_close(book);
    account_database_end(db);
    return error ? failed(error) : 0;
}

int account_recorded_end(void* opaque, pid_t child, int status) {
    (void)child;
    struct account_recorded_session* context = opaque;
    if (!context)
        return failed(EINVAL);
    struct account_session_lease* lease = context->lease;
    context->lease = NULL;
    return account_logbook_end(lease, status);
}

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/logbook.h
 * @brief   Account logbook interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines account logbook operations for recording and reading account
 * activity.
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
#ifndef AXIOM64_ACCOUNTS_LOGBOOK_H
#define AXIOM64_ACCOUNTS_LOGBOOK_H

#include "auth.h"
#include "login_record.h"

#ifndef ACCOUNT_LOGIN_JOURNAL_LIMIT
#define ACCOUNT_LOGIN_JOURNAL_LIMIT (32u * 1024 * 1024)
#endif
#ifndef ACCOUNT_LOGIN_LIVE_LIMIT
#define ACCOUNT_LOGIN_LIVE_LIMIT 1024u
#endif
#define ACCOUNT_LOGIN_ARCHIVE_LIMIT 4u
struct account_logbook;
struct account_session_lease;

// A root-only exclusive transaction validates the complete journal, repairs a
// partial trailing write, recovers leases whose last holder died, and publishes
// utmp/wtmp/btmp/auth.log projections. Complete corrupt frames fail closed.
// A full journal rotates durably into four retained closed generations. Live
// START records seed the new generation without duplicating historical events.
// Expiry of older generations is the explicit bounded retention policy.
int account_logbook_open(const char* directory, int create, struct account_logbook**);
void account_logbook_close(struct account_logbook*);
// Keep the book open while performing an administrative database transaction.
// Registration and administration use database -> logbook lock ordering.
int account_logbook_active(const struct account_logbook*, uid_t);
// A live lease is owned by the privileged supervisor. Create it after fork;
// neither the shell nor a daemon descended from it may inherit its descriptor.
// On a late error, output may still own a published lease and must be ended.
int account_logbook_begin(struct account_logbook*, const struct account_profile*, pid_t child,
                          const char* terminal, struct account_session_lease** output);
// A display manager opens its PAM session before starting the user process.
// The calling supervisor owns the lease and is the process recorded in utmp.
int account_logbook_begin_supervised(struct account_logbook*, const struct account_profile*,
                                     const char* terminal, struct account_session_lease** output);
// Consumes the lease even on error. Journal recovery reconciles a late failure.
int account_logbook_end(struct account_session_lease*, int wait_status);
// Never pass passwords, hashes, environment or arbitrary command arguments.
int account_logbook_audit(struct account_logbook*, enum account_login_kind, const char* name,
                          uid_t actor, const char* target, const char* terminal, int status);

#endif

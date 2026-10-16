// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_GUARD_H
#define AXIOM64_ACCOUNTS_GUARD_H
#include "database.h"
#include "logbook.h"

// Caller holds database then logbook throughout guard, mutation and commit.
// Live session leases and every real process/thread identity prevent structural
// account removal/renaming/home changes and numeric ID reuse. Password/lock,
// shell and membership policy updates can revoke future authentication live.
int account_guard_user(const struct account_database*, const struct account_logbook*, const char*);
int account_guard_group(const struct account_database*, const struct account_logbook*, const char*);
int account_guard_new_ids(const struct account_logbook*, uid_t, gid_t);

#endif

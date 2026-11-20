// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/guard.h
 * @brief   Account store guard interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the locks and file checks used to protect account store operations.
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

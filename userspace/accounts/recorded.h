// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/recorded.h
 * @brief   Recorded account operation interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares helpers that pair account operations with their logbook records.
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
#ifndef AXIOM64_ACCOUNTS_RECORDED_H
#define AXIOM64_ACCOUNTS_RECORDED_H

#include "logbook.h"
#include "session.h"

struct account_recorded_session {
    const char* database;
    const char* records;
    const struct account_profile* target;
    const struct account_profile* authorization;
    enum account_login_kind operation;
    uid_t actor;
    struct account_session_lease* lease;
};

// Session callbacks keep database -> logbook ordering. The authenticated
// revision must still be current when the child is registered. Administration
// holding those same transactions cannot pass the active-user guard in between.
int account_recorded_begin(void*, pid_t child, const char* terminal);
int account_recorded_end(void*, pid_t child, int wait_status);

#endif

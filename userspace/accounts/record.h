// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/record.h
 * @brief   Account record structures.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines parsed account identity fields and operations for accessing those
 * records.
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
#ifndef AXIOM64_ACCOUNTS_RECORD_H
#define AXIOM64_ACCOUNTS_RECORD_H

#include "database.h"
#include "store.h"

struct account_database {
    struct account_store* store;
    struct account_user* users;
    struct account_group* groups;
    size_t user_count, group_count;
    int fresh;
};

int account_record_decode(const struct account_content[ACCOUNT_FILE_COUNT],
                          struct account_database*);

int account_record_validate(const struct account_database*);

int account_record_encode(const struct account_database*,
                          struct account_content[ACCOUNT_FILE_COUNT]);

void account_record_free_files(struct account_content[ACCOUNT_FILE_COUNT]);

int account_record_user_valid(const struct account_user*);

void account_record_free_user(struct account_user*);

void account_record_free_group(struct account_group*);

#endif

// SPDX-License-Identifier: GPL-3.0-or-later
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

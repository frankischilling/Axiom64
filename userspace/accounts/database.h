// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_DATABASE_H
#define AXIOM64_ACCOUNTS_DATABASE_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define ACCOUNT_NAME_MAX 32

struct account_user {
    const char *name, *password, *gecos, *home, *shell;
    uid_t uid;
    gid_t gid;
    // Last change, minimum, maximum, warning, inactivity and account expiry.
    // Minus one means the corresponding shadow field is empty.
    int64_t age[6];
};

struct account_group {
    const char* name;
    gid_t gid;
    const uid_t* members;
    size_t member_count;
};

struct account_database;

// The database owns a locked store transaction. Fresh explicit provisioning
// starts with a locked root record and root group, without publishing them.
int account_database_begin(const char*, int provision, struct account_database**);

void account_database_end(struct account_database*);

int account_database_fresh(const struct account_database*);
const char* account_database_revision(const struct account_database*);
int account_database_recovery_error(const struct account_database*);

// Borrowed records remain valid until the next mutation or end of transaction.
const struct account_user* account_database_user(const struct account_database*, const char*);

const struct account_user* account_database_uid(const struct account_database*, uid_t);
// Enumeration follows the current transaction's owned record order.
const struct account_user* account_database_user_at(const struct account_database*, size_t);

const struct account_group* account_database_group(const struct account_database*, const char*);

const struct account_group* account_database_gid(const struct account_database*, gid_t);

// NULL previous means create; otherwise update the named record. Renaming or
// changing an ID also updates every dependent membership/primary-group record.
// Invalid input or failed allocation preserves the previous logical database.
int account_database_put_user(struct account_database*, const char* previous,
                              const struct account_user*);

int account_database_put_group(struct account_database*, const char* previous,
                               const struct account_group*);

int account_database_remove_user(struct account_database*, const char*);

int account_database_remove_group(struct account_database*, const char*);

int account_database_member(struct account_database*, const char* group, const char* user,
                            int present);

// Returns primary plus distinct supplementary IDs. ERANGE reports the required
// count through size, including for a NULL/zero-capacity query.
int account_database_groups(const struct account_database*, uid_t, gid_t*, size_t capacity,
                            size_t* size);

int account_database_commit(struct account_database*, int* published);
// Publish this user's new home and the complete generation through one durable
// protected intent. Recovery runs under the store lock on the next open.
int account_database_commit_home(struct account_database*, const char* user, int* published);

int account_name_valid(const char*);

int account_id_parse(const char*, uint32_t*);

#endif

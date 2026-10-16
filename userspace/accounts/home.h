// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_HOME_H
#define AXIOM64_ACCOUNTS_HOME_H

#include <sys/types.h>

struct account_home;

// Persist this initialized key in the account transaction's protected intent
// before creating a home. A matching trusted inode attribute proves creation
// across descriptor closure; inode numbers and ownership alone do not.
struct account_home_key {
    unsigned char bytes[16];
};

int account_home_key_new(struct account_home_key*);
// Validate absolute path spelling without touching the filesystem.
int account_home_path_valid(const char*);

// Only trusted root-owned ancestors are followed. The final parent must not be
// writable by another identity. Publish a prepared temporary directory without
// replacing an existing entry. Keep the returned receipt through the database
// commit, including after a creation error.
int account_home_create(const char*, uid_t, gid_t, struct account_home**);
int account_home_create_key(const char*, uid_t, gid_t, const struct account_home_key*,
                            struct account_home**);

// Consume the receipt. Keep a published home; otherwise remove only the empty
// directory identified by its still-open descriptor. An ambiguous creation or
// a replaced/nonempty entry is preserved and reported as a cleanup error.
int account_home_finish(struct account_home*, int published);

// A recovered transaction keeps its attested published home, or removes only
// matching empty staging/final directories. Missing, wrong or malformed
// attestations and nonempty entries are preserved and reported.
int account_home_recover(const char*, const struct account_home_key*, int published);

#endif

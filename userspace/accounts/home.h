// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_HOME_H
#define AXIOM64_ACCOUNTS_HOME_H

#include <sys/types.h>

struct account_home;

// Only trusted root-owned ancestors are followed. The final parent must not be
// writable by another identity. Publish a prepared temporary directory without
// replacing an existing entry. Keep the returned receipt through the database
// commit, including after a creation error.
int account_home_create(const char*, uid_t, gid_t, struct account_home**);

// Consume the receipt. Keep a published home; otherwise remove only the empty
// directory identified by its still-open descriptor. An ambiguous creation or
// a replaced/nonempty entry is preserved and reported as a cleanup error.
int account_home_finish(struct account_home*, int published);

#endif

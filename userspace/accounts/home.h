// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_HOME_H
#define AXIOM64_ACCOUNTS_HOME_H

#include <sys/types.h>

// Only trusted root-owned ancestors are followed. Existing final entries are
// rejected. Rollback removes only the created directory, never its contents.
int account_home_create(const char*, uid_t, gid_t, int* created);

int account_home_rollback(const char*, uid_t, gid_t);

#endif

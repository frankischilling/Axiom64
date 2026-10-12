// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_AUTH_H
#define AXIOM64_ACCOUNTS_AUTH_H

#include <stddef.h>
#include <sys/types.h>

struct account_profile {
    char *name, *home, *shell;
    uid_t uid;
    gid_t gid;
    gid_t* groups;
    size_t group_count;
    int password_change_required;
    char revision[35];
};

enum account_auth_result {
    ACCOUNT_AUTH_DENIED = 0,
    ACCOUNT_AUTH_ACCEPTED = 1,
    ACCOUNT_AUTH_CHANGE_REQUIRED = 2
};

// Root-owned database validation, maintained password verification, aging, and
// optional sudo-group authorization happen in one locked snapshot. No hash is
// retained in the returned owned profile. Operational failures return -1.
int account_auth_password(const char* database, const char* name, const char* password,
                          int require_sudo, struct account_profile**);

// A real/effective root administrator may assume an existing account without
// its password, including a locked service identity. This is not login auth.
int account_auth_root_switch(const char* database, const char* name, struct account_profile**);

void account_profile_free(struct account_profile*);

// Installs all real/effective/saved/filesystem IDs and supplementary groups.
// Nonroot targets lose all permitted/effective/inheritable/ambient capabilities.
// Service mode additionally prevents privilege acquisition through later exec.
// A failed transition is fatal to the calling child; it must never keep running.
int account_profile_enter(const struct account_profile*, int service);

// Replace inherited environment with login identity values and a fixed PATH.
int account_profile_environment(const struct account_profile*, const char* terminal);

#endif

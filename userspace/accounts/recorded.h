// SPDX-License-Identifier: GPL-3.0-or-later
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

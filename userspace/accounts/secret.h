// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_SECRET_H
#define AXIOM64_ACCOUNTS_SECRET_H

#include "password.h"

// Single-threaded interactive frontends supply their foreground controlling
// terminal, opened read/write. Echo, descriptor flags, signal actions and the
// caller's signal mask are restored on success, EOF, overlong input and
// cancellation. Failed output is cleared completely.
int account_secret_read(int terminal, const char* prompt, char output[ACCOUNT_PASSWORD_MAX + 1]);

#endif

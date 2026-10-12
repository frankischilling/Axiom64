// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_UPDATE_H
#define AXIOM64_ACCOUNTS_UPDATE_H

#include "auth.h"

// Updates revalidate authentication inside the locked database generation and
// record intent and completion without storing secrets in the audit journal.
// A NULL authorization requires a real root administrator. Otherwise the
// authenticated profile may change only its own password, including a forced
// change; normal minimum-age restrictions still apply.
// published reports a visible complete update even when later durability or
// audit publication fails. Callers must reauthenticate after any visible update.
int account_password_update(const char* database, const char* records,
                            const struct account_profile* target,
                            const struct account_profile* authorization, const char* password,
                            int* published);

// Explicit fresh-store provisioning creates locked root and a private-home
// administrator in sudo. Existing or damaged stores never restart provisioning.
int account_bootstrap(const char* database, const char* records, const char* name, const char* home,
                      const char* shell, const char* password, int* published);

#endif

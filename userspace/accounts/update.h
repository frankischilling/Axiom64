// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/update.h
 * @brief   Account update interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the requested account changes and exposes operations for applying
 * them.
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
// administrator in sudo. The installed desktop can also grant playback access.
// Existing or damaged stores never restart provisioning.
int account_bootstrap(const char* database, const char* records, const char* name, const char* home,
                      const char* shell, const char* password, int playback, int* published);

#endif

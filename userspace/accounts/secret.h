// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/secret.h
 * @brief   Secret input interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the terminal input and memory cleanup helpers used for passwords.
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
#ifndef AXIOM64_ACCOUNTS_SECRET_H
#define AXIOM64_ACCOUNTS_SECRET_H

#include "password.h"

// Single-threaded interactive frontends supply their foreground controlling
// terminal, opened read/write. Echo, descriptor flags, signal actions and the
// caller's signal mask are restored on success, EOF, overlong input and
// cancellation. Failed output is cleared completely.
int account_secret_read(int terminal, const char* prompt, char output[ACCOUNT_PASSWORD_MAX + 1]);

#endif

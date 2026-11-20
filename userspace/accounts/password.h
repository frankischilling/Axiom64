// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/password.h
 * @brief   Password handling interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares password checking and hashing operations used by account tools.
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
#ifndef AXIOM64_ACCOUNTS_PASSWORD_H
#define AXIOM64_ACCOUNTS_PASSWORD_H

#include <stddef.h>

#define ACCOUNT_PASSWORD_MAX 511
#define ACCOUNT_PASSWORD_HASH_SIZE 384

int account_password_hash(const char*, char output[ACCOUNT_PASSWORD_HASH_SIZE]);
// One means authenticated, zero means denied, minus one means an operational error.
int account_password_verify(const char*, const char* encoded);
void account_password_clear(void*, size_t);

#endif

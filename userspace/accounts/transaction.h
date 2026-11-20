// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/transaction.h
 * @brief   Account transaction interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares account transaction and recovery operations that maintain the store
 * across updates.
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
#ifndef AXIOM64_ACCOUNTS_TRANSACTION_H
#define AXIOM64_ACCOUNTS_TRANSACTION_H

#include <sys/types.h>

struct account_transaction;

// Internal store protocol: the caller holds its exclusive lock and lends the
// protected store descriptor. Current is empty for an unprovisioned store.
// Prepare durably records the home key and old/planned generations before
// creating a home. Keep an error receipt until finish/close consumes it.
int account_transaction_prepare(int directory, const char* current, const char* generation,
                                const char* path, uid_t, gid_t, struct account_transaction**);
// Recover a validated intent's home; retain its receipt, including a home
// recovery error, until the store checks/collects the associated generation.
int account_transaction_recover(int directory, const char* current, struct account_transaction**);
const char* account_transaction_generation(const struct account_transaction*);
int account_transaction_published(const struct account_transaction*, const char* current);
int account_transaction_mark_generation(const struct account_transaction*, int directory);
int account_transaction_check_generation(const struct account_transaction*, int directory);
// Finish rechecks home authority and synchronizes the actual store namespace
// before clearing only this receipt's intent. Close preserves pending intent.
int account_transaction_finish(struct account_transaction*, const char* current);
void account_transaction_close(struct account_transaction*);

#endif

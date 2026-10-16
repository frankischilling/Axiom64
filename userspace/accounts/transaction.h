// SPDX-License-Identifier: GPL-3.0-or-later
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

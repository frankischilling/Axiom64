// SPDX-License-Identifier: GPL-3.0-or-later
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

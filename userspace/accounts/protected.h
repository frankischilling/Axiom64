// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_ACCOUNTS_PROTECTED_H
#define AXIOM64_ACCOUNTS_PROTECTED_H

#include <sys/types.h>

// Root effective/filesystem UID and GID are required. Ancestors are walked by
// descriptor without symlinks or dot components. Only root-owned sticky
// ancestors may be writable by other identities; the final mode is exact.
int account_directory_open(const char*, mode_t mode, int create);
// One-component names, regular root-owned single-link files and exact modes.
// Creation never changes the ownership/mode of an existing entry.
int account_file_open(int directory, const char* name, int flags, mode_t mode, int create);
// Validate an existing entry; a missing entry is permitted for publication.
int account_file_check(int directory, const char* name, mode_t mode);
// Write a new inode, synchronize it, publish by rename and synchronize its
// parent. writer runs with a private root-owned descriptor. On a late error,
// the complete projection may already be visible; its journal is authoritative.
int account_file_publish(int directory, const char* name, mode_t mode, int (*writer)(int, void*),
                         void* context);
int account_nonce(unsigned char bytes[16]);
void account_nonce_name(char output[35], char prefix, const unsigned char bytes[16]);

#endif

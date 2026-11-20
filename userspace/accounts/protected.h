// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/accounts/protected.h
 * @brief   Protected account file interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares validation and opening of files that contain restricted account
 * data.
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
// A separate read-only check for a root-owned, single-link mode-04755 worker.
// It never creates an executable or changes an existing entry's metadata.
int account_executable_open(int directory, const char* name);
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

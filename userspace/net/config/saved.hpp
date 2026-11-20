// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/config/saved.hpp
 * @brief   Saved network profile interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares reading and persistence of network configuration profiles.
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
#pragma once
#include <stddef.h>

// Internal saved-profile policy. Public configuration/resolver journals use
// their own Store contract and do not acquire this private-file policy.
namespace ax::net::saved {
int read(const char* directory, const char* name, char*, size_t, size_t&);
int write(const char* directory, const char* name, const void*, size_t);
int remove(const char* directory, const char* name);

// Internal singleton ownership: validate/create a permanent private lock inode,
// acquire an exclusive nonblocking open-description lock, and transfer its fd.
// Never rename, truncate, or unlink the inode. Output is unchanged on failure.
int lock(const char* directory, const char* name, int& descriptor);
} // namespace ax::net::saved

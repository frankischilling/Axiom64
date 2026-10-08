// SPDX-License-Identifier: GPL-3.0-or-later
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

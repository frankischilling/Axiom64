// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>

// Internal saved-profile policy. Public configuration/resolver journals use
// their own Store contract and do not acquire this private-file policy.
namespace ax::net::saved {
int read(const char* directory, const char* name, char*, size_t, size_t&);
int write(const char* directory, const char* name, const void*, size_t);
int remove(const char* directory, const char* name);
} // namespace ax::net::saved

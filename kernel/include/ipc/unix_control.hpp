// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "ipc/unix_credentials.hpp"

namespace ax {
class UnixRights;
// Success transfers captured descriptions to rights. Failure releases every
// partial capture and leaves the caller's control unchanged.
int unix_read_control(Task&, uint64_t pointer, size_t length, UnixMessageCredentials&,
                      UnixRights*& rights);
size_t unix_write_control(Task&, const UnixMessageCredentials*, const UnixRights*,
                          bool pass_credentials, uint64_t pointer, size_t capacity, bool cloexec,
                          uint32_t& flags);
} // namespace ax

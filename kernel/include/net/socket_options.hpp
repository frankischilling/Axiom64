// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Task;

// Read-only device query with Linux length, name and ordered copy-fault behavior.
int socket_device_option(Task&, unsigned index, uint64_t value, uint64_t length);
} // namespace ax

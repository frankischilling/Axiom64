// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Task;

// Read-only device query with Linux length, name and ordered copy-fault behavior.
int socket_device_option(Task&, unsigned index, uint64_t value, uint64_t length);

// Publish a bounded scalar result length before copying its value.
// The caller validates and selects its protocol-specific capacity.
int socket_integer_result(Task&, int value, uint32_t capacity, uint64_t value_pointer,
                          uint64_t length_pointer);
} // namespace ax

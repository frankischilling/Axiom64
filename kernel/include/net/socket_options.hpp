// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Task;

// Publish the selected byte count before copying page-bounded value prefixes.
int socket_bytes_result(Task&, const void*, uint32_t length, uint32_t capacity,
                        uint64_t value_pointer, uint64_t length_pointer);

// Read-only device query with Linux length, name and ordered copy-fault behavior.
int socket_device_option(Task&, unsigned index, uint64_t value, uint64_t length);

// Publish a bounded scalar result length before copying its value.
// The caller validates and selects its protocol-specific capacity.
int socket_integer_result(Task&, int value, uint32_t capacity, uint64_t value_pointer,
                          uint64_t length_pointer);
} // namespace ax

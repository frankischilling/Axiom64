// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Task;

// Read-only device query with Linux length, name and ordered copy-fault behavior.
int socket_device_option(Task&, unsigned index, uint64_t value, uint64_t length);

// IPv6 scalar getters publish the clamped length before copying the value.
int socket_ipv6_integer(Task&, int value, uint32_t capacity, uint64_t value_pointer,
                        uint64_t length_pointer);
} // namespace ax

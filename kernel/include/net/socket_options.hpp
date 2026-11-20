// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/socket_options.hpp
 * @brief   Socket option access interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares validation and marshaling for socket option values.
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

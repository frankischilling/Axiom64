// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/proc/integer.hpp
 * @brief   Proc sysctl integer codecs.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the integer parsing and partial-read helpers used by proc control
 * files.
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

namespace ax::proc {
bool parse_integer(const char*, size_t, bool unsigned_value, int32_t&, size_t& consumed);
bool parse_unsigned_long(const char*, size_t, uint64_t&, size_t& consumed);
int64_t read_integer(int32_t, uint64_t& offset, void*, size_t);
int64_t read_unsigned_long(uint64_t, uint64_t& offset, void*, size_t);
} // namespace ax::proc

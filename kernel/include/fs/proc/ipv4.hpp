// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/proc/ipv4.hpp
 * @brief   IPv4 proc sysctl interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the IPv4 configuration properties and scope operations exposed by
 * procfs.
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

namespace ax::proc4 {
constexpr unsigned property_count = 3, forwarding_property = 1;
const char* property_name(unsigned);
const char* scope_name(unsigned cookie);
bool scope_index(const char*, unsigned&);
uint64_t scope_generation(unsigned);
int64_t read(unsigned index, unsigned property, uint64_t& offset, void*, size_t);
int64_t write(unsigned index, unsigned property, uint64_t& offset, const void*, size_t);

int64_t source_limit_read(uint64_t& offset, void*, size_t);
int64_t source_limit_write(uint64_t& offset, const void*, size_t);
} // namespace ax::proc4

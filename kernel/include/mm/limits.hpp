// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/mm/limits.hpp
 * @brief   Virtual memory limit interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares address-space and memory-lock accounting operations used by mappings
 * and processes.
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
#include <stddef.h>
#include <stdint.h>

namespace ax {
struct Task;

bool memory_growth_allowed(const Task&, uint64_t start, size_t length, bool replace = false);

bool data_growth_allowed(const Task&, uint64_t start, size_t length, bool replace = false);

bool memory_protection_allowed(const Task&, uint64_t start, size_t length, int protection);

bool heap_change_allowed(const Task&, uint64_t address);
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/mm/remap.hpp
 * @brief   Linux virtual mapping resize interface.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Declares the handler for resizing anonymous and memory-file mappings.
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

int64_t remap_memory(Task&, uint64_t address, size_t old_size, size_t new_size, uint64_t flags);
} // namespace ax

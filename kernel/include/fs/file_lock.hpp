// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/file_lock.hpp
 * @brief   Whole-file lock interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines file lock operations and the lifetime hooks used by open
 * descriptions.
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
#include "fs/vfs.hpp"

namespace ax {
// Serialized by the current single-CPU syscall/scheduler execution model.
// Locks belong to descriptions, use canonical nodes, and remain advisory.
bool file_lock_operation(uint32_t);

int file_lock_try(Handle*, uint32_t);

void file_lock_release(Handle*);
} // namespace ax

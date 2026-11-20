// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/shared_memory.hpp
 * @brief   System V shared memory interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares segment creation, attachment, controls, and process lifecycle hooks.
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
#include "process/task.hpp"

namespace ax {
int64_t shared_memory_syscall(Frame*);
bool shared_memory_fork(Task& child, const Task& parent);
void shared_memory_release(Task&);
int shared_memory_unmap(Task&, uint64_t base, size_t length);
int shared_memory_protect(Task&, uint64_t base, size_t length, int protection);
} // namespace ax

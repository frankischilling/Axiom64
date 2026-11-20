// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/mm/stack.hpp
 * @brief   Userspace stack layout interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares stack location and bounds checks for the process address space.
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
struct AddressSpace;

// Resolve only the current task's anonymous grow-down stack mappings.
bool grow_user_stack(const AddressSpace&, uint64_t address, size_t length, bool write,
                     bool execute = false);

// Normalize Linux mprotect flags and extend a grow-down request within its mapping.
int memory_protection_range(const AddressSpace&, uint64_t& address, uint64_t& length,
                            uint64_t& protection);
} // namespace ax

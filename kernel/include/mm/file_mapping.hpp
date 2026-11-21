// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/mm/file_mapping.hpp
 * @brief   File-backed address-space ranges.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Tracks file references across mapping splits, forks, and teardown.
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
struct Handle;
struct Node;

struct FileMapping {
    AddressSpace* space;
    FileMapping* next = nullptr;
    uint64_t start, end, offset;
    Handle* description = nullptr;

    // Memory-file mappings also participate in their backing object's list.
    Node* memory_file = nullptr;
    FileMapping* file_next = nullptr;
    bool shared = false, may_write = false;
};

void attach_file_mapping(FileMapping&);
void move_file_mapping(FileMapping&, uint64_t start, size_t length);
// Unmap the pages and trim or release every intersecting file range.
int unmap_file_mappings(AddressSpace&, uint64_t base, size_t length);
bool clone_file_mappings(AddressSpace&, const AddressSpace&);
void release_file_mappings(AddressSpace&);
} // namespace ax

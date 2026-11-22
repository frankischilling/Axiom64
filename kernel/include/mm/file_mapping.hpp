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
struct Mount;
struct Node;
struct Task;

struct FileMapping {
    AddressSpace* space;
    FileMapping* next = nullptr;
    uint64_t start, end, offset;
    Handle* description = nullptr;

    // Demand-paged mappings also participate in their backing object's list.
    Node* memory_file = nullptr;
    Node* disk_file = nullptr;
    FileMapping* file_next = nullptr;
    bool shared = false, may_write = false, no_execute = false;
};

void attach_file_mapping(FileMapping&);
void move_file_mapping(FileMapping&, uint64_t start, size_t length);
// Unmap the pages and trim or release every intersecting file range.
int unmap_file_mappings(AddressSpace&, uint64_t base, size_t length);
bool clone_file_mappings(AddressSpace&, const AddressSpace&);
void release_file_mappings(AddressSpace&);

int map_disk_file(Task&, Handle&, uint64_t base, size_t length, uint64_t offset, int protection,
                  bool shared, bool replace);
void invalidate_disk_pages(Node&, uint64_t first, uint64_t end, bool shrink = false);
void overlay_disk_pages(Node&, uint64_t offset, void* buffer, size_t length);
int flush_disk_pages(Mount&, Node* = nullptr, uint64_t first = 0, uint64_t end = UINT64_MAX);
void discard_disk_pages(Node&, uint64_t first);
int sync_file_mappings(AddressSpace&, uint64_t start, size_t length, unsigned flags);
int64_t write_disk_page(Node&, uint64_t offset, const void* buffer, size_t length);
int flush_disk_device(Node&);
uint64_t file_page_permissions(uint64_t);
uint64_t file_page_protection(uint64_t, int protection);
uint64_t unpopulated_file_page(const FileMapping&, int protection);

enum class FileFault { outside, protection, bus, resolved };
FileFault file_mapping_fault(AddressSpace&, uint64_t address, bool write, bool execute);
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/residency.cpp
 * @brief   Report userspace page residency.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Reads virtual mappings and file residency without faulting in the queried pages.
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
#include "mm/residency.hpp"

#include "fs/vfs.hpp"
#include "mm/file_mapping.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
bool can_report_residency(const Task& task, const FileMapping& mapping) {
    auto node = mapping.memory_file ? mapping.memory_file : file_node(mapping.description->node);
    const auto& credentials = task.credentials;
    return credentials.user.filesystem == node->uid || capable(credentials, Capability::fowner) ||
           (!node_readonly(node) && node_access(node, 2) == 0);
}
} // namespace

int mapped_residency(Task& task, uint64_t start, size_t length, uint64_t vector) {
    if (start % page_size)
        return -22;
    if (start > user_limit || length > user_limit - start)
        return -12;
    size_t pages = align_up(length) / page_size;
    if (vector > user_limit || pages > user_limit - vector)
        return -14;

    auto& space = task.memory->space;
    auto file = space.file_mappings;
    uint8_t residency[page_size];
    while (pages) {
        while (file && file->end <= start)
            file = file->next;
        size_t count = min(pages, sizeof(residency));
        const auto mapping = file && file->start <= start ? file : nullptr;
        if (file) {
            const auto boundary = mapping ? mapping->end : file->start;
            count = min(count, size_t((boundary - start) / page_size));
        }
        // Linux hides cache state for files the caller does not own or have write access to.
        const bool hidden = mapping && !can_report_residency(task, *mapping);
        size_t mapped = 0;
        for (; mapped < count; ++mapped) {
            const uint64_t address = start + mapped * page_size;
            const auto entry = space.entry(address);
            if (!entry || !(*entry & page_mapping))
                break;
            residency[mapped] = hidden || (*entry & page_mask) ||
                                (mapping && file_page_resident(*mapping, address));
        }
        if (mapped && !space.copy_out(vector, residency, mapped))
            return -14;
        if (mapped != count)
            return -12;
        pages -= count;
        vector += count;
        start += count * page_size;
    }
    return 0;
}
} // namespace ax

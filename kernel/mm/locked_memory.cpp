// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/locked_memory.cpp
 * @brief   Lock userspace mappings and account for their resident pages.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Applies Linux range and resource limits before faulting in accessible pages.
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
#include "mm/limits.hpp"

#include "process/task.hpp"

namespace ax {
bool memory_lock_growth_allowed(const Task& task, size_t length) {
    if (capable(task.credentials, Capability::ipc_lock))
        return true;
    const auto limit = align_down(task.process->limits.soft(Resource::locked_memory));
    const auto used = task.memory->space.locked_size();
    return used <= limit && length <= limit - used;
}

int update_memory_lock(AddressSpace& space, uint64_t start, size_t length, bool lock) {
    for (uint64_t page = start; page < start + length; page += page_size) {
        auto entry = space.entry(page);
        if (!entry || !(*entry & page_mapping))
            return -12;
        if (!lock)
            *entry &= ~page_locked;
        else if (!(*entry & 0x200)) // Device mappings do not use allocator-backed pages.
            *entry |= page_locked;
    }
    return 0;
}

int populate_locked_pages(AddressSpace& space, uint64_t start, size_t length) {
    for (uint64_t page = start; page < start + length; page += page_size) {
        auto entry = space.entry(page);
        if (!entry || !(*entry & page_mapping))
            return -12;
        if (!(*entry & page_locked))
            continue;
        // Prefault a writable private file page through its copy-on-write path.
        const auto writable_file = page_file | page_private | page_file_write;
        const bool write = (*entry & writable_file) == writable_file;
        if (!space.valid(page, page_size, write))
            return -12;
    }
    return 0;
}

int set_memory_lock(Task& task, uint64_t address, size_t length, bool lock) {
    if (lock && !task.process->limits.soft(Resource::locked_memory) &&
        !capable(task.credentials, Capability::ipc_lock))
        return -1;
    if (address > user_limit || length > user_limit - address)
        return -12;
    const uint64_t start = align_down(address);
    length = align_up(address + length) - start;
    if (!length)
        return 0;

    auto& space = task.memory->space;
    if (lock && !memory_lock_growth_allowed(task, length - space.locked_size(start, length)))
        return -12;
    if (int error = update_memory_lock(space, start, length, lock))
        return error;
    return lock ? populate_locked_pages(space, start, length) : 0;
}
} // namespace ax

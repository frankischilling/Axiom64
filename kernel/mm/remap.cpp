// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/remap.cpp
 * @brief   Private anonymous mremap implementation.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Resizes ordinary anonymous mappings and relocates their pages when needed.
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
#include "mm/remap.hpp"
#include "mm/limits.hpp"
#include "process/task.hpp"

namespace ax {
int64_t remap_anonymous(Task& task, uint64_t address, size_t old_size, size_t new_size,
                        uint64_t flags) {
    constexpr uint64_t may_move = 1, fixed = 2, dont_unmap = 4;
    constexpr uint64_t nx = 1ull << 63;
    constexpr uint64_t access = 1 | 2 | nx;

    if ((flags & ~(may_move | fixed | dont_unmap)) ||
        ((flags & (fixed | dont_unmap)) && !(flags & may_move)) || address % page_size ||
        !old_size || !new_size)
        return -22;
    if (old_size > mmap_length_limit || new_size > mmap_length_limit)
        return -12;
    old_size = align_up(old_size);
    new_size = align_up(new_size);
    if ((flags & dont_unmap) && old_size != new_size)
        return -22;
    if (flags & (fixed | dont_unmap))
        return -38;
    if (address >= user_limit || old_size > user_limit - address)
        return -14;

    auto& space = task.memory->space;
    uint64_t end = address + old_size;
    uint64_t protection_bits = 0;
    for (uint64_t page = address; page < end; page += page_size) {
        auto entry = space.entry(page);
        if (!entry || !(*entry & (page_mask | page_file)))
            return -14;
        if ((*entry & (page_private | page_anonymous | page_file)) !=
            (page_private | page_anonymous))
            return -38;
        if (page == address)
            protection_bits = *entry & access;
        else if (new_size > old_size && (*entry & access) != protection_bits)
            return -14;
    }

    if (new_size <= old_size) {
        if (new_size < old_size)
            space.unmap(address + new_size, old_size - new_size);
        return address;
    }

    size_t growth = new_size - old_size;
    int protection = (protection_bits & 1 ? 1 : 0) | (protection_bits & 2 ? 2 : 0) |
                     (protection_bits & nx ? 0 : 4);
    if (!memory_growth_allowed(task, end, growth) ||
        ((protection & 2) && !data_growth_allowed(task, end, growth)))
        return -12;
    if (growth <= user_limit - end && !space.mapped_size(end, growth))
        return space.map(end, growth, protection, page_private | page_anonymous) ? int64_t(address)
                                                                                 : -12;
    if (!(flags & may_move))
        return -12;

    uint64_t destination = space.find_unmapped(new_size);
    if (!destination ||
        !space.move_anonymous_mapping(address, old_size, destination, new_size, protection))
        return -12;
    space.next_map = destination + new_size + page_size;
    return destination;
}
} // namespace ax

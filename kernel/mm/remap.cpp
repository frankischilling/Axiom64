// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/remap.cpp
 * @brief   Resize private anonymous and memory-file mappings.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Keeps existing pages and backing references when a mapping changes address.
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
#include "mm/file_mapping.hpp"
#include "mm/limits.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
FileMapping* demand_paged_range(AddressSpace& space, uint64_t start, uint64_t end) {
    auto map = space.file_mappings;
    while (map && map->end <= start)
        map = map->next;
    return map && map->start == start && map->end == end && (map->memory_file || map->disk_file)
               ? map
               : nullptr;
}

bool grow_file_mapping(FileMapping& map, uint64_t destination, size_t new_size, int protection) {
    auto& space = *map.space;
    size_t old_size = map.end - map.start;
    bool moved = destination != map.start;
    uint64_t tail = destination + old_size;
    if (!space.prepare_mapping(moved ? destination : tail, moved ? new_size : new_size - old_size))
        return false;

    // Reserve the new range before moving resident pages. New pages fault
    // against the original file, preserving its offsets and access checks.
    uint64_t initial = unpopulated_file_page(map, protection);
    for (uint64_t page = tail; page < destination + new_size; page += page_size)
        *space.entry(page) = initial;
    if (moved) {
        space.move_prepared_pages(map.start, destination, old_size);
        move_file_mapping(map, destination, new_size);
    } else
        map.end += new_size - old_size;
    return true;
}
} // namespace

int64_t remap_memory(Task& task, uint64_t address, size_t old_size, size_t new_size,
                     uint64_t flags) {
    constexpr uint64_t may_move = 1, fixed = 2, dont_unmap = 4;
    constexpr uint64_t nx = 1ull << 63;

    if ((flags & ~(may_move | fixed | dont_unmap)) ||
        ((flags & (fixed | dont_unmap)) && !(flags & may_move)) || address % page_size ||
        !old_size || !new_size)
        return -22;
    if (old_size > anonymous_reservation_limit || new_size > anonymous_reservation_limit)
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
    auto first = space.entry(address);
    if (!first || !(*first & page_mapping))
        return -14;
    bool file_backed = *first & page_file;
    bool reserve = !file_backed && (*first & page_anonymous_deferred);
    if (!reserve && (old_size > mmap_length_limit || new_size > mmap_length_limit))
        return -12;
    auto file = file_backed ? demand_paged_range(space, address, end) : nullptr;
    if (file_backed && !file)
        return -14;
    uint64_t readable = file ? page_file_access : 1;
    uint64_t writable = file ? page_file_write : 2;
    uint64_t protection_bits = 0;
    for (uint64_t page = address; page < end; page += page_size) {
        auto entry = space.entry(page);
        if (!entry || !(*entry & page_mapping))
            return -14;
        if (file ? !(*entry & page_file)
                 : (*entry & (page_private | page_anonymous | page_file)) !=
                       (page_private | page_anonymous))
            return -38;
        uint64_t read_bit = !file && !(*entry & page_mask) ? page_anonymous_access : readable;
        uint64_t bits =
            (*entry & (writable | nx | page_locked)) | (*entry & read_bit ? readable : 0);
        if (page == address)
            protection_bits = bits;
        else if (new_size > old_size && bits != protection_bits)
            return -14;
    }

    if (new_size <= old_size) {
        if (new_size < old_size) {
            if (file) {
                if (int error = unmap_file_mappings(space, address + new_size, old_size - new_size))
                    return error;
            } else {
                space.unmap(address + new_size, old_size - new_size);
                space.trim_page_tables(address + new_size, old_size - new_size);
            }
        }
        return address;
    }

    size_t growth = new_size - old_size;
    const bool locked = protection_bits & page_locked;
    if (locked && !memory_lock_growth_allowed(task, growth))
        return -11;
    int protection = (protection_bits & readable ? 1 : 0) | (protection_bits & writable ? 2 : 0) |
                     (protection_bits & nx ? 0 : 4);
    if (file && new_size - 1 > uint64_t(INT64_MAX) - file->offset)
        return -75;
    if (!memory_growth_allowed(task, end, growth) ||
        ((protection & 2) && (!file || !file->shared) && !data_growth_allowed(task, end, growth)))
        return -12;
    auto finish = [&](uint64_t base) -> int64_t {
        if (locked) {
            const auto tail = base + old_size;
            update_memory_lock(space, tail, growth, true);
            populate_locked_pages(space, tail, growth);
        }
        return base;
    };
    if (growth <= user_limit - end && !space.mapped_size(end, growth)) {
        if (file)
            return grow_file_mapping(*file, address, new_size, protection) ? finish(address) : -12;
        bool grown = reserve ? space.map_anonymous_reservation(end, growth, protection)
                             : space.map(end, growth, protection, page_private | page_anonymous);
        return grown ? finish(address) : -12;
    }
    if (!(flags & may_move))
        return -12;

    uint64_t destination = space.find_unmapped(new_size);
    if (!destination)
        return -12;
    bool moved = file ? grow_file_mapping(*file, destination, new_size, protection)
                      : space.move_anonymous_mapping(address, old_size, destination, new_size,
                                                     protection, reserve);
    if (!moved)
        return -12;
    space.next_map = destination + new_size + page_size;
    return finish(destination);
}
} // namespace ax

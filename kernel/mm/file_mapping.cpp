// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/file_mapping.cpp
 * @brief   Ownership of mapped file ranges.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Keeps a backing reference per surviving virtual range and drops it after unmap.
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
#include "mm/file_mapping.hpp"
#include "fs/memfd.hpp"
#include "fs/vfs.hpp"

namespace ax {
namespace {
void retain_backing(FileMapping& mapping) {
    if (mapping.memory_file)
        memfd_link_mapping(mapping);
    else
        retain(mapping.description);
}

void release_mapping(FileMapping& mapping) {
    if (mapping.memory_file)
        memfd_unlink_mapping(mapping);
    else
        close_handle(mapping.description);
    release(&mapping);
}

void insert_range(FileMapping& mapping) {
    auto link = &mapping.space->file_mappings;
    while (*link && (*link)->start < mapping.start)
        link = &(*link)->next;
    mapping.next = *link;
    *link = &mapping;
}
} // namespace

void attach_file_mapping(FileMapping& mapping) {
    insert_range(mapping);
    retain_backing(mapping);
}

void move_file_mapping(FileMapping& mapping, uint64_t start, size_t length) {
    auto link = &mapping.space->file_mappings;
    while (*link != &mapping)
        link = &(*link)->next;
    *link = mapping.next;
    mapping.start = start;
    mapping.end = start + length;
    insert_range(mapping);
}

int unmap_file_mappings(AddressSpace& space, uint64_t base, size_t length) {
    uint64_t end = base + length;
    FileMapping* suffix = nullptr;
    // Nonoverlapping ranges allow at most one split and one fallible allocation.
    for (auto map = space.file_mappings; map && map->start < end; map = map->next)
        if (map->start < base && map->end > end) {
            suffix = static_cast<FileMapping*>(alloc(sizeof(FileMapping)));
            if (!suffix)
                return -12;
            break;
        }

    space.unmap(base, length);
    auto link = &space.file_mappings;
    while (auto map = *link) {
        if (map->start >= end)
            break;
        if (map->end <= base) {
            link = &map->next;
            continue;
        }
        if (map->start >= base && map->end <= end) {
            *link = map->next;
            release_mapping(*map);
            continue;
        }
        if (map->start < base) {
            if (map->end > end) {
                *suffix = *map;
                suffix->offset += end - map->start;
                suffix->start = end;
                map->next = suffix;
                retain_backing(*suffix);
            }
            map->end = base;
        } else {
            map->offset += end - map->start;
            map->start = end;
        }
        link = &map->next;
    }
    return 0;
}

bool clone_file_mappings(AddressSpace& dest, const AddressSpace& source) {
    auto tail = &dest.file_mappings;
    for (auto map = source.file_mappings; map; map = map->next) {
        auto copy = static_cast<FileMapping*>(alloc(sizeof(FileMapping)));
        if (!copy)
            return false;
        *copy = *map;
        copy->space = &dest;
        copy->next = nullptr;
        *tail = copy;
        tail = &copy->next;
        retain_backing(*copy);
    }
    return true;
}

void release_file_mappings(AddressSpace& space) {
    while (auto map = space.file_mappings) {
        space.file_mappings = map->next;
        release_mapping(*map);
    }
}
} // namespace ax

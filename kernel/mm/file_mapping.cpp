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
#include "ipc/shared_memory.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr uint64_t nx = 1ull << 63;
constexpr uint64_t shared_page = 0x400, deny_write = 0x800;

void retain_backing(FileMapping& mapping) {
    if (mapping.memory_file)
        memfd_link_mapping(mapping);
    else
        retain(mapping.description);
    if (mapping.disk_file) {
        mapping.file_next = mapping.disk_file->shared_mappings;
        mapping.disk_file->shared_mappings = &mapping;
    }
}

void release_mapping(FileMapping& mapping) {
    if (mapping.disk_file) {
        auto link = &mapping.disk_file->shared_mappings;
        while (*link != &mapping)
            link = &(*link)->file_next;
        *link = mapping.file_next;
    }
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

uint64_t read_disk_page(Node& node, uint64_t offset) {
    // Resident aliases supply the cache. Each PTE owns one reference, so an
    // inode with no mappings retains no pages.
    for (auto map = node.shared_mappings; map; map = map->file_next) {
        if (offset < map->offset || offset - map->offset >= map->end - map->start)
            continue;
        uint64_t page = *map->space->entry(map->start + offset - map->offset) & page_mask;
        if (page)
            return page_try_retain(page) ? page : 0;
    }

    uint64_t page = page_alloc();
    if (!page)
        return 0;
    size_t count = min(page_size, node.size - offset);
    if (node_read(&node, offset, physical(page), count) != int64_t(count)) {
        page_free(page);
        return 0;
    }
    page_account_shared(page);
    return page;
}
} // namespace

uint64_t file_page_permissions(uint64_t pte) {
    pte &= ~3ull;
    if ((pte & page_mask) && (pte & page_file_access))
        pte |= 1;
    if ((pte & page_file_write) && !(pte & page_file_cow))
        pte |= 2;
    return pte;
}

uint64_t file_page_protection(uint64_t pte, int prot) {
    pte &= ~(nx | page_file_access | page_file_write);
    if (!(prot & 4))
        pte |= nx;
    if (prot & 7)
        pte |= page_file_access;
    if (prot & 2)
        pte |= page_file_write;
    return file_page_permissions(pte);
}

uint64_t unpopulated_file_page(const FileMapping& map, int prot) {
    uint64_t flags = page_file | 4;
    if (!map.shared)
        flags |= page_private | page_file_cow;
    else if (!map.may_write)
        flags |= deny_write;
    if (map.no_execute)
        flags |= page_no_execute;
    return file_page_protection(flags, prot);
}

int map_disk_file(Task& task, Handle& handle, uint64_t base, size_t length, uint64_t offset,
                  int prot, bool replace) {
    if (prot & 2)
        return -19;
    if (offset > INT64_MAX || length - 1 > uint64_t(INT64_MAX) - offset)
        return -75;
    auto& space = task.memory->space;
    auto map = static_cast<FileMapping*>(alloc(sizeof(FileMapping)));
    if (!map || !space.prepare_mapping(base, length)) {
        release(map);
        return -12;
    }
    if (replace) {
        if (int error = shared_memory_unmap(task, base, length)) {
            release(map);
            return error;
        }
    }
    auto node = file_node(handle.node);
    *map = {.space = &space,
            .start = base,
            .end = base + length,
            .offset = offset,
            .description = &handle,
            .disk_file = node,
            .shared = true,
            .no_execute = node->mount->noexec};
    uint64_t initial = unpopulated_file_page(*map, prot);
    for (uint64_t va = base; va < base + length; va += page_size)
        *space.entry(va) = initial;
    attach_file_mapping(*map);
    return 0;
}

FileFault file_mapping_fault(AddressSpace& space, uint64_t address, bool write, bool execute) {
    auto pte = space.entry(address);
    if (!pte || !(*pte & page_file))
        return FileFault::outside;
    if (!(*pte & page_file_access) || (write && !(*pte & page_file_write)) ||
        (execute && (*pte & nx)))
        return FileFault::protection;
    auto map = space.file_mappings;
    while (map && map->end <= address)
        map = map->next;
    if (!map || address < map->start)
        panic("file PTE without a mapping");
    uint64_t offset = align_down(address) - map->start + map->offset;
    if (map->memory_file)
        return memfd_fault(*map, offset, *pte, write);
    if (!map->disk_file)
        panic("file PTE without backing");
    if (offset >= map->disk_file->size)
        return FileFault::bus;
    if (*pte & page_mask)
        return FileFault::protection;
    uint64_t page = read_disk_page(*map->disk_file, offset);
    if (!page)
        return FileFault::bus;
    *pte = file_page_permissions(*pte | shared_page | page);
    if (read_cr3() == space.root)
        write_cr3(space.root);
    return FileFault::resolved;
}

void invalidate_disk_pages(Node& node, uint64_t first, uint64_t end) {
    if (first >= end)
        return;
    first = align_down(first);
    for (auto map = node.shared_mappings; map; map = map->file_next) {
        uint64_t limit = min(end, map->offset + (map->end - map->start));
        bool invalidated = false;
        for (uint64_t offset = max(first, map->offset); offset < limit; offset += page_size) {
            auto pte = map->space->entry(map->start + offset - map->offset);
            if (uint64_t page = *pte & page_mask) {
                *pte = file_page_permissions(*pte & ~(page_mask | shared_page));
                page_free(page);
                invalidated = true;
            }
        }
        if (invalidated && read_cr3() == map->space->root)
            write_cr3(map->space->root);
    }
}

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

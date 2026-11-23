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
#include "mm/tlb_batch.hpp"
#include "fs/memfd.hpp"
#include "fs/vfs.hpp"
#include "ipc/shared_memory.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr uint64_t nx = 1ull << 63;
constexpr uint64_t shared_page = 0x400, deny_write = 0x800;

struct DirtyDiskPage {
    DirtyDiskPage* next;
    Node* node;
    Handle* description;
    uint64_t offset, page;
};

DirtyDiskPage* dirty_disk_pages;

DirtyDiskPage* dirty_disk_page(Node& node, uint64_t offset) {
    for (auto dirty = dirty_disk_pages; dirty; dirty = dirty->next)
        if (dirty->node == &node && dirty->offset == offset)
            return dirty;
    return nullptr;
}

bool track_disk_write(FileMapping& map, uint64_t offset, uint64_t page) {
    auto& node = *map.disk_file;
    if (!map.may_write || node_readonly(&node) || node.exec_images)
        return false;
    if (auto dirty = dirty_disk_page(node, offset))
        return dirty->page == page;
    auto dirty = static_cast<DirtyDiskPage*>(alloc(sizeof(DirtyDiskPage)));
    if (!dirty)
        return false;
    if (!page_try_retain(page)) {
        release(dirty);
        return false;
    }
    if (prepare_regular_write(current_task(), &node)) {
        page_free(page);
        release(dirty);
        return false;
    }
    retain(map.description);
    *dirty = {dirty_disk_pages, &node, map.description, offset, page};
    dirty_disk_pages = dirty;
    return true;
}

void finish_disk_write(DirtyDiskPage** link) {
    auto dirty = *link;
    // Revoke page writes before dropping the dirty reference. A later write
    // through any alias has to register the page again.
    for (auto map = dirty->node->disk_mappings; map; map = map->file_next) {
        if (!map->shared || !map->may_write || !map->space->root || dirty->offset < map->offset ||
            dirty->offset - map->offset >= map->end - map->start)
            continue;
        const uint64_t address = map->start + dirty->offset - map->offset;
        auto pte = map->space->entry(address);
        if (pte && (*pte & page_mask) == dirty->page) {
            *pte = file_page_permissions(*pte | page_file_cow);
            sync_user_translations(map->space->root, address);
        }
    }
    *link = dirty->next;
    page_free(dirty->page);
    close_handle(dirty->description);
    release(dirty);
}

void retain_backing(FileMapping& mapping) {
    if (mapping.memory_file)
        memfd_link_mapping(mapping);
    else
        retain(mapping.description);
    if (mapping.disk_file) {
        mapping.file_next = mapping.disk_file->disk_mappings;
        mapping.disk_file->disk_mappings = &mapping;
    }
}

void release_mapping(FileMapping& mapping) {
    if (mapping.disk_file) {
        auto link = &mapping.disk_file->disk_mappings;
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

uint64_t resident_disk_page(Node& node, uint64_t offset) {
    if (auto dirty = dirty_disk_page(node, offset))
        return dirty->page;
    // Resident aliases supply the cache. Each PTE owns one reference, so an
    // inode with no mappings retains no pages.
    for (auto map = node.disk_mappings; map; map = map->file_next) {
        if (offset < map->offset || offset - map->offset >= map->end - map->start)
            continue;
        auto pte = map->space->entry(map->start + offset - map->offset);
        if (pte && (*pte & shared_page))
            return *pte & page_mask;
    }
    return 0;
}

uint64_t read_disk_page(Node& node, uint64_t offset) {
    if (uint64_t page = resident_disk_page(node, offset))
        return page_try_retain(page) ? page : 0;
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

bool file_page_resident(const FileMapping& map, uint64_t address) {
    const uint64_t offset = map.offset + (address - map.start);
    if (map.memory_file)
        return memfd_page_resident(*map.memory_file, offset);
    return map.disk_file && offset < map.disk_file->size &&
           resident_disk_page(*map.disk_file, offset);
}

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
    else if (map.disk_file)
        flags |= page_file_cow;
    if (map.no_execute)
        flags |= page_no_execute;
    return file_page_protection(flags, prot);
}

int map_disk_file(Task& task, Handle& handle, uint64_t base, size_t length, uint64_t offset,
                  int prot, bool shared, bool replace) {
    auto node = file_node(handle.node);
    const bool may_write = shared && (handle.flags & 3) == 2 && !node_readonly(node);
    if (shared && (prot & 2) && !may_write)
        return -13;
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
    *map = {.space = &space,
            .start = base,
            .end = base + length,
            .offset = offset,
            .description = &handle,
            .disk_file = node,
            .shared = shared,
            .may_write = may_write,
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
    uint64_t state = *pte;
    uint64_t old = state & page_mask;
    const bool first_write = write && (state & page_file_cow);
    if (old && !first_write)
        return FileFault::protection;
    uint64_t source = old ? old : read_disk_page(*map->disk_file, offset);
    if (!source)
        return FileFault::bus;
    uint64_t page = source;
    if (first_write && map->shared) {
        if (!track_disk_write(*map, offset, page)) {
            if (!old)
                page_free(page);
            return FileFault::bus;
        }
        state = (state & ~page_file_cow) | shared_page;
    } else if (first_write) {
        page = page_alloc();
        if (!page) {
            if (!old)
                page_free(source);
            return FileFault::bus;
        }
        memcpy(physical(page), physical(source), page_size);
        if (!old)
            page_free(source);
        state &= ~(page_file_cow | shared_page);
    } else
        state |= shared_page;
    *pte = file_page_permissions((state & ~page_mask) | page);
    sync_user_translations(space.root, align_down(address));
    if (old && old != page)
        page_free(old);
    return FileFault::resolved;
}

void invalidate_disk_pages(Node& node, uint64_t first, uint64_t end, bool shrink) {
    if (first >= end)
        return;
    uint64_t first_removed = align_up(first);
    first = align_down(first);
    for (auto map = node.disk_mappings; map; map = map->file_next) {
        uint64_t limit = min(end, map->offset + (map->end - map->start));
        TlbBatch batch(map->space->root);
        bool invalidated = false;
        for (uint64_t offset = max(first, map->offset); offset < limit; offset += page_size) {
            auto pte = map->space->entry(map->start + offset - map->offset);
            uint64_t page = *pte & page_mask;
            // A private copy survives file writes and a partial-page shrink.
            if (!page || (!(*pte & shared_page) && !(shrink && offset >= first_removed)))
                continue;
            uint64_t flags = *pte & ~(page_mask | shared_page);
            if (!map->shared || map->may_write)
                flags |= page_file_cow;
            *pte = file_page_permissions(flags);
            batch.retire(page);
            invalidated = true;
        }
        if (invalidated)
            batch.finish();
    }
}

void overlay_disk_pages(Node& node, uint64_t offset, void* buffer, size_t length) {
    auto output = static_cast<uint8_t*>(buffer);
    for (auto dirty = dirty_disk_pages; dirty; dirty = dirty->next) {
        if (dirty->node != &node)
            continue;
        auto start = max(offset, dirty->offset);
        auto end = min(offset + length, dirty->offset + page_size);
        if (start < end)
            memcpy(output + start - offset,
                   static_cast<const uint8_t*>(physical(dirty->page)) + start - dirty->offset,
                   end - start);
    }
}

int flush_disk_pages(Mount& mount, Node* node, uint64_t first, uint64_t end) {
    if (first >= end)
        return 0;
    first = align_down(first);
    for (auto link = &dirty_disk_pages; *link;) {
        auto dirty = *link;
        if (dirty->node->mount != &mount || (node && dirty->node != node) ||
            dirty->offset < first || dirty->offset >= end) {
            link = &dirty->next;
            continue;
        }
        if (dirty->offset < dirty->node->size) {
            size_t length = min(page_size, dirty->node->size - dirty->offset);
            int64_t written =
                write_disk_page(*dirty->node, dirty->offset, physical(dirty->page), length);
            if (written != int64_t(length))
                return written < 0 ? int(written) : -5;
        }
        finish_disk_write(link);
    }
    return 0;
}

void discard_disk_pages(Node& node, uint64_t first) {
    for (auto link = &dirty_disk_pages; *link;) {
        if ((*link)->node == &node && (*link)->offset >= first)
            finish_disk_write(link);
        else
            link = &(*link)->next;
    }
}

int sync_file_mappings(AddressSpace& space, uint64_t start, size_t length, unsigned flags) {
    constexpr unsigned async = 1, invalidate = 2, sync = 4;
    if (start % page_size || (flags & ~(async | invalidate | sync)) ||
        (flags & (async | sync)) == (async | sync))
        return -22;
    if (!length)
        return 0;
    if (start >= user_limit || length > user_limit - start)
        return -12;
    length = align_up(length);
    const uint64_t end = start + length;
    if (flags & sync)
        for (auto map = space.file_mappings; map && map->start < end; map = map->next) {
            if (map->end <= start || !map->disk_file || !map->shared)
                continue;
            auto& node = *map->disk_file;
            uint64_t first = map->offset + (max(start, map->start) - map->start);
            uint64_t last = map->offset + (min(end, map->end) - map->start);
            if (int error = flush_disk_pages(*node.mount, &node, first, last))
                return error;
            if (int error = flush_disk_device(node))
                return error;
        }
    return space.mapped_size(start, length) == length ? 0 : -12;
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

    for (auto map = space.file_mappings; map && map->start < end; map = map->next) {
        if (map->end <= base || !map->disk_file || !map->shared || !map->may_write)
            continue;
        auto& node = *map->disk_file;
        auto first = map->offset + (max(base, map->start) - map->start);
        auto last = map->offset + (min(end, map->end) - map->start);
        // Keep any unwritten dirty pages available for a later sync.
        flush_disk_pages(*node.mount, &node, first, last);
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
        if (auto node = map->disk_file; node && map->shared && map->may_write)
            flush_disk_pages(*node->mount, node, map->offset,
                             map->offset + (map->end - map->start));
        release_mapping(*map);
    }
}
} // namespace ax

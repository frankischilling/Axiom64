// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/mmio.cpp
 * @brief   Installs uncached device mappings after checking the whole range.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Stages new page tables and preserves existing compatible entries.
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
#include "mm/mmio.hpp"
#include "boot/boot.hpp"

namespace ax::Mmio {
namespace {
constexpr uint64_t high_canonical = 0xffff800000000000ull;
constexpr size_t max_bytes = 1024 * 1024;
constexpr size_t max_pages = max_bytes / page_size + 1;
constexpr uint64_t present = 1, writable = 2, user = 4;
constexpr uint64_t pwt = 8, pcd = 16, pat_or_large = 1ull << 7, nx = 1ull << 63;

unsigned cache_index(uint64_t entry) {
    return (entry & pat_or_large ? 4 : 0) | ((entry >> 3) & 3);
}

bool cache_is_uc(CacheLayout cache, unsigned slot) {
    return slot < (cache.pat ? 8u : 4u) && ((cache.types >> (8 * slot)) & 0xff) == 0;
}

bool uc_flags(CacheLayout cache, uint64_t& flags) {
    unsigned index = 3;
    if (!cache_is_uc(cache, index)) {
        index = 0;
        while (index < 8 && !cache_is_uc(cache, index))
            ++index;
        if (index == 8)
            return false;
    }
    flags = ((index & 1) ? pwt : 0) | ((index & 2) ? pcd : 0) | ((index & 4) ? pat_or_large : 0);
    return true;
}

bool matches(uint64_t entry, uint64_t physical, CacheLayout cache) {
    constexpr uint64_t permissions = present | writable | user | nx;
    return (entry & page_mask) == physical && (entry & permissions) == (present | writable | nx) &&
           cache_is_uc(cache, cache_index(entry));
}

bool mapping_cache_flags(uint64_t address, uint64_t physical, uint64_t table,
                         uint64_t physical_limit, const PageTables& ops, uint64_t& flags) {
    for (int shift = 39; shift >= 12; shift -= 9) {
        if (!table || table >= physical_limit)
            return false;
        const auto entry = ops.table(ops.context, table)[(address >> shift) & 511];
        if (!(entry & present))
            return false;
        if (shift == 12) {
            flags = entry & leaf_cache_mask;
            return (entry & page_mask) == physical;
        }
        if (entry & pat_or_large) {
            if (shift == 39)
                return false;
            const uint64_t offsets = (1ull << shift) - 1;
            const uint64_t large_pat = 1ull << 12;
            flags = (entry & (pwt | pcd)) | ((entry & large_pat) ? pat_or_large : 0);
            return ((entry & page_mask & ~offsets) | (address & offsets)) == physical;
        }
        table = entry & page_mask;
    }
    return false;
}

struct NewTable {
    uint64_t* parent;
    uint64_t physical;
};

struct StagedTables {
    const PageTables& ops;
    uint64_t physical_limit;
    // A <=1 MiB request can touch at most two entries at each parent level.
    NewTable entries[6];
    size_t count = 0;

    uint64_t* child(uint64_t& entry) {
        uint64_t physical;
        if (entry) {
            if ((entry & (present | writable | pat_or_large)) != (present | writable))
                return nullptr; // Keep large, read-only, and software-owned entries intact.
            physical = entry & page_mask;
            return physical && physical < physical_limit ? ops.table(ops.context, physical)
                                                         : nullptr;
        }
        for (size_t i = 0; i < count; ++i)
            if (entries[i].parent == &entry)
                return ops.table(ops.context, entries[i].physical);
        if (count == sizeof(entries) / sizeof(*entries))
            return nullptr;
        physical = ops.allocate(ops.context);
        if (!physical)
            return nullptr;
        entries[count++] = {&entry, physical};
        return ops.table(ops.context, physical);
    }

    void discard() {
        while (count)
            ops.release(ops.context, entries[--count].physical);
    }

    void publish() {
        while (count) {
            const auto& entry = entries[--count];
            *entry.parent = entry.physical | present | writable;
        }
    }
};
} // namespace

bool range(uint64_t address, size_t length, uint64_t direct, uint64_t physical_limit, Range& out) {
    if (!length || length > max_bytes || (direct & (page_size - 1)) || address >= physical_limit ||
        length > physical_limit - address || address > UINT64_MAX - direct ||
        length - 1 > UINT64_MAX - direct - address || direct + address < high_canonical)
        return false;
    const auto first = align_down(address);
    const auto last = align_down(address + length - 1);
    out = {first, direct + first, (last - first) / page_size + 1};
    return true;
}

bool permits(const Range& span, const BootInfo& boot) {
    const uint64_t end = span.physical_page + span.pages * page_size;
    for (size_t i = 0; i < boot.memory_count; ++i) {
        const auto entry = boot.memory_at(boot.memory_context, i);
        if (!entry.length || entry.base >= end)
            continue;
        if (entry.kind == BootMemoryKind::reserved || entry.kind == BootMemoryKind::firmware ||
            entry.kind == BootMemoryKind::mapped_reserved)
            continue;
        if (entry.base >= span.physical_page || entry.length > span.physical_page - entry.base)
            return false;
    }
    return true;
}

bool alias_cache_flags(const Range& span, uint64_t root, uint64_t physical_limit,
                       const PageTables& ops, uint64_t& flags) {
    if (!span.pages || (span.virtual_page % page_size) || (span.physical_page % page_size) ||
        span.physical_page >= physical_limit ||
        span.pages > (physical_limit - span.physical_page) / page_size ||
        span.pages - 1 > (UINT64_MAX - span.virtual_page) / page_size ||
        !mapping_cache_flags(span.virtual_page, span.physical_page, root, physical_limit, ops,
                             flags))
        return false;
    for (size_t i = 1; i < span.pages; ++i) {
        const uint64_t offset = i * page_size;
        uint64_t next;
        if (!mapping_cache_flags(span.virtual_page + offset, span.physical_page + offset, root,
                                 physical_limit, ops, next) ||
            next != flags)
            return false;
    }
    return true;
}

bool install(const Range& span, uint64_t root, uint64_t physical_limit, CacheLayout cache,
             const PageTables& ops) {
    uint64_t cache_flags;
    if (!span.pages || span.pages > max_pages || !uc_flags(cache, cache_flags))
        return false;
    auto* root_table = ops.table(ops.context, root);
    StagedTables staged{ops, physical_limit, {}};
    uint64_t* leaves[max_pages]{};
    for (size_t i = 0; i < span.pages; ++i) {
        const auto offset = i * page_size;
        const auto va = span.virtual_page + offset;
        auto* table = root_table;
        for (int shift = 39; table && shift > 12; shift -= 9)
            table = staged.child(table[(va >> shift) & 511]);
        if (!table) {
            staged.discard();
            return false;
        }
        auto& entry = table[(va >> 12) & 511];
        if (!entry)
            leaves[i] = &entry;
        else if (!matches(entry, span.physical_page + offset, cache)) {
            staged.discard();
            return false;
        }
    }

    // Validation and allocation are complete. Link the private tables only after
    // their leaves are ready. Leave compatible hardware accessed/dirty bits intact.
    for (size_t i = 0; i < span.pages; ++i)
        if (leaves[i])
            *leaves[i] =
                (span.physical_page + i * page_size) | present | writable | nx | cache_flags;
    staged.publish();
    for (size_t i = 0; i < span.pages; ++i)
        if (leaves[i])
            ops.invalidate(ops.context, span.virtual_page + i * page_size);
    return true;
}
} // namespace ax::Mmio

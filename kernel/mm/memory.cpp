// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/memory.cpp
 * @brief   Physical and virtual memory management.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Manages page allocation, page tables, address spaces, and copies across the
 * userspace boundary.
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
#include "boot/boot.hpp"
#include "mm/dma.hpp"
#include "mm/file_mapping.hpp"
#include "mm/mmio.hpp"
#include "mm/stack.hpp"
#include "fs/memfd.hpp"

namespace ax {
uint64_t direct_map;
static constexpr size_t max_pages = (4ull * 1024 * 1024 * 1024) / page_size;
static uint8_t bitmap[max_pages / 8];
static uint8_t shared_bitmap[max_pages / 8];
static uint16_t page_references[max_pages];
static size_t search_page = 1;
static uint64_t kernel_root;
static uint64_t cpu_physical_limit;
static Mmio::CacheLayout mmio_cache;
static size_t total_pages, free_pages, shared_pages;

static bool used(size_t p) {
    return bitmap[p / 8] & (1u << (p % 8));
}

static void mark(size_t p, bool allocated) {
    if (allocated)
        bitmap[p / 8] |= 1u << (p % 8);
    else
        bitmap[p / 8] &= ~(1u << (p % 8));
}

void memory_init() {
    if (!boot_info.direct_offset || !boot_info.memory_at || !boot_info.memory_count)
        panic("missing memory map");
    direct_map = boot_info.direct_offset;
    kernel_root = read_cr3() & page_mask;
    cpu_physical_limit = physical_address_limit();
    uint32_t a = 1, b, c, d;
    asm volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    const bool pat = d & (1u << 16);
    mmio_cache = {pat ? rdmsr(0x277) : 0x0007040600070406ull, pat};
    memset(bitmap, 0xff, sizeof(bitmap));
    total_pages = 0;
    for (size_t i = 0; i < boot_info.memory_count; i++) {
        auto e = boot_info.memory_at(boot_info.memory_context, i);
        if (e.kind != BootMemoryKind::usable)
            continue;
        uint64_t end = min(align_down(e.base + e.length) / page_size, uint64_t(max_pages));
        for (uint64_t p = max(align_up(e.base) / page_size, uint64_t(1)); p < end; p++) {
            if (used(p)) {
                mark(p, false);
                total_pages++;
            }
        }
    }
    free_pages = total_pages;
    log("Memory: %u MiB available, isolated four-level paging\n", uint64_t(total_pages / 256));
}

PhysicalMemoryStats physical_memory_stats() {
    return {total_pages * page_size, free_pages * page_size, shared_pages * page_size};
}

void activate_kernel_memory() {
    write_cr3(kernel_root);
}

void* map_mmio(uint64_t address, size_t length) {
    Mmio::Range range;
    if (!Mmio::range(address, length, direct_map, cpu_physical_limit, range) ||
        !Mmio::permits(range, boot_info))
        return nullptr;
    const Mmio::PageTables tables{
        nullptr, [](void*, uint64_t page) { return static_cast<uint64_t*>(physical(page)); },
        [](void*) { return page_alloc(); }, [](void*, uint64_t page) { page_free(page); },
        [](void*, uint64_t va) { asm volatile("invlpg (%0)" ::"r"(va)
                                              : "memory"); }};
    return Mmio::install(range, kernel_root, cpu_physical_limit, mmio_cache, tables)
               ? physical(address)
               : nullptr;
}

static uint64_t allocate_pages(size_t count, size_t ceiling, size_t boundary_pages = 0) {
    if (!count || count > free_pages)
        return 0;
    const auto start = Dma::find_free_run(bitmap, ceiling, search_page, count, boundary_pages);
    if (!start)
        return 0;
    for (size_t page = start; page < start + count; ++page) {
        mark(page, true);
        page_references[page] = 1;
    }
    free_pages -= count;
    search_page = start + count;
    const uint64_t address = start * page_size;
    memset(physical(address), 0, count * page_size);
    return address;
}

uint64_t page_alloc(size_t count) {
    return allocate_pages(count, max_pages);
}

uint64_t Dma::allocate(size_t count, Limits limits) {
    if (limits.boundary && (!power_of_two(limits.boundary) || limits.boundary < page_size))
        return 0;
    const auto ceiling = min(min(limits.end, cpu_physical_limit) / page_size, uint64_t(max_pages));
    return allocate_pages(count, ceiling, limits.boundary / page_size);
}

void page_account_shared(uint64_t p, size_t count) {
    const size_t start = p / page_size;
    if (p % page_size || start >= max_pages || count > max_pages - start)
        panic("invalid shared page range");
    for (size_t index = start; index < start + count; index++) {
        if (!page_references[index])
            panic("shared accounting requires an allocated page");
        uint8_t& flags = shared_bitmap[index / 8];
        const uint8_t bit = 1u << (index % 8);
        if (!(flags & bit)) {
            flags |= bit;
            shared_pages++;
        }
    }
}

void page_free(uint64_t p, size_t count) {
    if (!p || p % page_size || p / page_size + count > max_pages)
        panic("invalid physical free");
    for (size_t i = 0; i < count; i++) {
        auto index = p / page_size + i;
        if (!page_references[index])
            panic("physical page double free");
        if (!--page_references[index]) {
            mark(index, false);
            free_pages++;
            uint8_t& flags = shared_bitmap[index / 8];
            const uint8_t bit = 1u << (index % 8);
            if (flags & bit) {
                flags &= ~bit;
                shared_pages--;
            }
        }
    }
    search_page = min(search_page, size_t(p / page_size));
}

void page_retain(uint64_t p, size_t count) {
    if (!p || p % page_size || p / page_size + count > max_pages)
        panic("invalid page retain");
    for (size_t i = 0; i < count; i++) {
        auto& refs = page_references[p / page_size + i];
        if (!refs || refs == 65535)
            panic("invalid page reference");
        refs++;
    }
}

bool page_try_retain(uint64_t p) {
    if (!p || p % page_size || p / page_size >= max_pages)
        panic("invalid page retain");
    auto& refs = page_references[p / page_size];
    if (!refs)
        panic("invalid page reference");
    if (refs == UINT16_MAX)
        return false;
    ++refs;
    return true;
}

unsigned page_reference_count(uint64_t p) {
    return p && p / page_size < max_pages ? page_references[p / page_size] : 0;
}

bool page_shared(uint64_t p, size_t count) {
    if (!p || p / page_size + count > max_pages)
        return false;
    for (size_t i = 0; i < count; i++)
        if (page_references[p / page_size + i] > 1)
            return true;
    return false;
}

void* alloc(size_t size) {
    if (size > SIZE_MAX - 16 - page_size)
        return nullptr;
    size_t n = align_up(size + 16) / page_size;
    uint64_t p = page_alloc(n);
    if (!p)
        return nullptr;
    auto header = (uint64_t*)physical(p);
    header[0] = n;
    header[1] = 0x4158494f4d484541;
    return header + 2;
}

void release(void* address) {
    if (!address)
        return;
    auto header = (uint64_t*)address - 2;
    if (header[1] != 0x4158494f4d484541)
        panic("invalid heap free");
    page_free(uint64_t(header) - direct_map, header[0]);
}

bool AddressSpace::create() {
    root = page_alloc();
    if (!root)
        return false;
    auto dest = (uint64_t*)physical(root), src = (uint64_t*)physical(kernel_root);
    memcpy(dest + 256, src + 256, 256 * sizeof(uint64_t));
    next_map = 0x100000000;
    return true;
}

uint64_t* AddressSpace::entry(uint64_t va, bool create_table) {
    if (!root || va >= user_limit)
        return nullptr;
    auto table = (uint64_t*)physical(root);
    for (int shift = 39; shift > 12; shift -= 9) {
        auto& item = table[(va >> shift) & 511];
        if (!(item & 1)) {
            if (!create_table)
                return nullptr;
            uint64_t p = page_alloc();
            if (!p)
                return nullptr;
            item = p | 7;
        }
        if (item & 128)
            return nullptr;
        table = (uint64_t*)physical(item & page_mask);
    }
    return &table[(va >> 12) & 511];
}

static uint64_t mapped_length(uint64_t table, unsigned level, uint64_t base, uint64_t start,
                              uint64_t end, bool private_data = false, bool make_writable = false) {
    const auto entries = static_cast<const uint64_t*>(physical(table));
    uint64_t span = 1ull << (12 + (level - 1) * 9), result = 0;
    for (unsigned i = 0; i < (level == 4 ? 256u : 512u); i++) {
        uint64_t address = base + i * span;
        if (!(entries[i] & (page_mask | page_file)) || address >= end || address + span <= start)
            continue;
        if (level == 1 || (entries[i] & 128)) {
            bool writable = entries[i] & ((entries[i] & page_file) ? page_file_write : 2);
            if (!private_data || ((entries[i] & page_private) && !(entries[i] & page_stack) &&
                                  (make_writable || writable)))
                result += min(end, address + span) - max(start, address);
        } else
            result += mapped_length(entries[i] & page_mask, level - 1, address, start, end,
                                    private_data, make_writable);
    }
    return result;
}

uint64_t AddressSpace::mapped_size(uint64_t start, uint64_t length) const {
    if (start > user_limit || length > user_limit - start)
        return UINT64_MAX;
    return root && length ? mapped_length(root, 4, 0, start, start + length) : 0;
}

static uint64_t first_mapping(uint64_t table, unsigned level, uint64_t base, uint64_t start,
                              uint64_t end) {
    const auto entries = static_cast<const uint64_t*>(physical(table));
    uint64_t span = 1ull << (12 + (level - 1) * 9);
    unsigned last = (end - 1 - base) / span;
    for (unsigned slot = (start - base) / span; slot <= last; ++slot) {
        if (!(entries[slot] & (page_mask | page_file)))
            continue;
        uint64_t address = base + slot * span;
        uint64_t first = max(start, address);
        if (level == 1 || (entries[slot] & 128))
            return first;
        first = first_mapping(entries[slot] & page_mask, level - 1, address, first,
                              min(end, address + span));
        if (first != user_limit)
            return first;
    }
    return user_limit;
}

uint64_t AddressSpace::find_unmapped(size_t length) const {
    if (!root || !length)
        return 0;
    for (uint64_t start = next_map; start < user_limit && length <= user_limit - start;) {
        uint64_t occupied = first_mapping(root, 4, 0, start, start + length);
        if (occupied == user_limit)
            return start;
        start = occupied + page_size;
    }
    return 0;
}

uint64_t AddressSpace::private_writable_size(uint64_t start, uint64_t length,
                                             bool make_writable) const {
    if (start > user_limit || length > user_limit - start)
        return UINT64_MAX;
    return root && length ? mapped_length(root, 4, 0, start, start + length, true, make_writable)
                          : 0;
}

static uint64_t permissions(int prot) {
    return 4 | ((prot & 3) ? 1 : 0) | ((prot & 2) ? 2 : 0) | ((prot & 4) ? 1 : (1ull << 63));
}

static void release_empty_tables(uint64_t table, unsigned level, uint64_t base, uint64_t start,
                                 uint64_t end) {
    auto entries = static_cast<uint64_t*>(physical(table));
    uint64_t span = 1ull << (12 + (level - 1) * 9);
    for (size_t i = (start - base) / span; i <= (end - base - 1) / span; i++) {
        auto& entry = entries[i];
        if (!(entry & 1) || (entry & 128))
            continue;
        uint64_t child = entry & page_mask;
        uint64_t address = base + i * span;
        if (level > 2)
            release_empty_tables(child, level - 1, address, max(start, address),
                                 min(end, address + span));
        auto children = static_cast<const uint64_t*>(physical(child));
        size_t used = 0;
        while (used < 512 && !(children[used] & (page_mask | page_file)))
            used++;
        if (used == 512) {
            entry = 0;
            page_free(child);
        }
    }
}

static void discard_empty_tables(AddressSpace& space, uint64_t start, uint64_t end) {
    release_empty_tables(space.root, 4, 0, start, end);
    if (read_cr3() == space.root)
        write_cr3(space.root);
}

bool AddressSpace::map(uint64_t va, size_t len, int prot, uint64_t mapping_flags) {
    if (!prepare_mapping(va, len))
        return false;
    uint64_t end = va + align_up(len);
    // Pending entries are nonpresent and have no user or file bits set.
    constexpr uint64_t pending = 1ull << 59;
    for (uint64_t p = va; p < end; p += page_size) {
        auto& e = *entry(p);
        if ((e & page_mask) && !(e & page_file))
            continue;
        uint64_t physical_page = e & page_file ? 0 : page_alloc();
        if (!physical_page) {
            for (uint64_t previous = va; previous < p; previous += page_size) {
                auto& candidate = *entry(previous);
                if ((candidate & pending) && !(candidate & 4)) {
                    uint64_t allocated = candidate & page_mask;
                    candidate = 0;
                    page_free(allocated);
                }
            }
            discard_empty_tables(*this, va, end);
            return false;
        }
        e = physical_page | pending;
    }
    for (uint64_t p = va; p < end; p += page_size) {
        auto& e = *entry(p);
        e = (e & (page_mask | (page_software & ~page_private))) | permissions(prot) | mapping_flags;
    }
    if (read_cr3() == root)
        write_cr3(root);
    return true;
}

bool AddressSpace::move_anonymous_mapping(uint64_t source, size_t old_size, uint64_t destination,
                                          size_t new_size, int protection) {
    // The caller has checked the source and found a free, disjoint destination.
    if (!prepare_mapping(destination, new_size))
        return false;
    if (!map(destination + old_size, new_size - old_size, protection,
             page_private | page_anonymous)) {
        discard_empty_tables(*this, destination, destination + new_size);
        return false;
    }
    move_prepared_pages(source, destination, old_size);
    return true;
}

void AddressSpace::move_prepared_pages(uint64_t source, uint64_t destination, size_t size) {
    // The destination has empty page-table slots and needs no more allocation.
    for (size_t offset = 0; offset < size; offset += page_size) {
        auto& old = *entry(source + offset);
        *entry(destination + offset) = old;
        old = 0;
    }
    discard_empty_tables(*this, source, source + size);
}

bool AddressSpace::prepare_mapping(uint64_t va, size_t len) {
    if (va % page_size || va < page_size || va >= user_limit || len > user_limit - va)
        return false;
    uint64_t end = va + align_up(len);
    constexpr uint64_t leaf_span = 512 * page_size;
    for (uint64_t address = va; address < end; address = (address | (leaf_span - 1)) + 1) {
        if (!entry(address, true)) {
            if (root)
                discard_empty_tables(*this, va, end);
            return false;
        }
    }
    return true;
}

bool AddressSpace::map_physical(uint64_t va, uint64_t pa, size_t len, int prot, bool external) {
    if (pa % page_size || !prepare_mapping(va, len))
        return false;
    for (uint64_t offset = 0; offset < len; offset += page_size) {
        auto e = entry(va + offset);
        if (!external)
            page_retain(pa + offset);
        if ((*e & page_mask) && !(*e & 0x200))
            page_free(*e & page_mask);
        *e = (pa + offset) | permissions(prot) | (external ? 0x200 : 0x400);
    }
    if (read_cr3() == root)
        write_cr3(root);
    return true;
}

void AddressSpace::unmap(uint64_t va, size_t len) {
    if (va >= user_limit || len > user_limit - va)
        return;
    for (uint64_t p = align_down(va); p < va + len; p += page_size) {
        auto e = entry(p);
        if (e && (*e & (page_mask | page_file))) {
            if ((*e & page_mask) && !(*e & 0x200))
                page_free(*e & page_mask);
            *e = 0;
        }
    }
    if (read_cr3() == root)
        write_cr3(root);
}

bool AddressSpace::protect(uint64_t va, size_t len, int prot) {
    if (va % page_size || va >= user_limit || len > user_limit - va)
        return false;
    for (uint64_t p = va; p < va + len; p += page_size) {
        auto e = entry(p);
        if (!e || !(*e & (page_mask | page_file)) || ((prot & 2) && (*e & 0x800)) ||
            ((prot & 4) && (*e & page_no_execute)))
            return false;
    }
    for (uint64_t p = va; p < va + len; p += page_size) {
        auto e = entry(p);
        *e = *e & page_file ? memfd_page_protection(*e, prot)
                            : (*e & (page_mask | page_software)) | permissions(prot);
    }
    if (read_cr3() == root)
        write_cr3(root);
    return true;
}

bool AddressSpace::valid(uint64_t va, size_t len, bool write) const {
    if (va >= user_limit || len > user_limit - va)
        return false;
    auto& space = *const_cast<AddressSpace*>(this);
    for (uint64_t p = align_down(va); p < va + len; p += page_size) {
        auto e = space.entry(p);
        if (e && ((*e & 5) == 5) && (!write || (*e & 2)))
            continue;
        if (e && (*e & page_file)) {
            if (memfd_fault(space, p, write, false) != MemfdFault::resolved)
                return false;
        } else if (!grow_user_stack(*this, max(p, va), 1, write)) {
            return false;
        }
    }
    return true;
}

uint64_t AddressSpace::retain_readable_page(uint64_t address) {
    if (!valid(address, 1))
        return 0;
    uint64_t mapping = *entry(address);
    // External device mappings have no allocator reference to retain.
    if (mapping & 0x200)
        return 0;
    uint64_t page = mapping & page_mask;
    return page_try_retain(page) ? page : 0;
}

bool AddressSpace::copy_in(void* dst, uint64_t src, size_t len) const {
    if (!valid(src, len))
        return false;
    auto d = (uint8_t*)dst;
    while (len) {
        auto e = const_cast<AddressSpace*>(this)->entry(src);
        size_t n = min(len, size_t(page_size - (src % page_size)));
        memcpy(d, (uint8_t*)physical(*e & page_mask) + src % page_size, n);
        d += n;
        src += n;
        len -= n;
    }
    return true;
}

bool AddressSpace::copy_out(uint64_t dst, const void* src, size_t len) const {
    if (!valid(dst, len, true))
        return false;
    auto s = (const uint8_t*)src;
    while (len) {
        auto e = const_cast<AddressSpace*>(this)->entry(dst);
        size_t n = min(len, size_t(page_size - (dst % page_size)));
        memcpy((uint8_t*)physical(*e & page_mask) + dst % page_size, s, n);
        s += n;
        dst += n;
        len -= n;
    }
    return true;
}

bool AddressSpace::string(uint64_t src, char* dst, size_t cap) const {
    for (size_t i = 0; i < cap; i++) {
        if (!copy_in(dst + i, src + i, 1))
            return false;
        if (!dst[i])
            return true;
    }
    return false;
}

static void destroy_table(uint64_t phys, int level) {
    auto t = (uint64_t*)physical(phys);
    size_t end = level == 4 ? 256 : 512;
    for (size_t i = 0; i < end; i++)
        if (t[i] & page_mask) {
            if (level > 1)
                destroy_table(t[i] & page_mask, level - 1);
            else if (!(t[i] & 0x200))
                page_free(t[i] & page_mask);
        }
    page_free(phys);
}

void AddressSpace::destroy() {
    if (root) {
        destroy_table(root, 4);
        root = 0;
    }
    release_file_mappings(*this);
}

static bool clone_table(uint64_t dest, uint64_t src, int level) {
    auto d = (uint64_t*)physical(dest), s = (uint64_t*)physical(src);
    size_t end = level == 4 ? 256 : 512;
    for (size_t i = 0; i < end; i++) {
        if (!(s[i] & page_mask)) {
            if (level == 1 && (s[i] & page_file))
                d[i] = s[i];
            continue;
        }
        if (level == 1 && (s[i] & 0x600)) {
            d[i] = s[i];
            if (!(s[i] & 0x200))
                page_retain(s[i] & page_mask);
            continue;
        }
        uint64_t p = page_alloc();
        if (!p)
            return false;
        d[i] = p | (s[i] & ~page_mask);
        if (level > 1) {
            if (!clone_table(p, s[i] & page_mask, level - 1))
                return false;
        } else
            memcpy(physical(p), physical(s[i] & page_mask), page_size);
    }
    return true;
}

bool AddressSpace::clone_from(const AddressSpace& src) {
    if (!create())
        return false;
    if (!clone_table(root, src.root, 4) || !clone_file_mappings(*this, src)) {
        destroy();
        return false;
    }
    next_map = src.next_map;
    return true;
}
} // namespace ax

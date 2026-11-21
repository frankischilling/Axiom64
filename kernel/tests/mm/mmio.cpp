// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/mm/mmio.cpp
 * @brief   Checks x86 MMIO address, cache, and rollback policy.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Exercises production MMIO page walks against an instrumented table allocator.
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
#include "mm/mmio.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <vector>

namespace {
using namespace ax;
using Mmio::Range;

constexpr uint64_t direct = 0xffff800000000000ull;
constexpr uint64_t limit = 1ull << 36;
constexpr uint64_t nx = 1ull << 63;
constexpr uint64_t uc_page = nx | 0x1b;
constexpr Mmio::CacheLayout normal{0x0007040600070406ull, true};

struct Fixture {
    using Table = std::array<uint64_t, 512>;
    std::array<Table, 13> memory{};
    std::array<bool, 13> owned{};
    std::vector<uint64_t> flushes;
    size_t pending = 0;
    int remaining = -1;

    Fixture() {
        owned[1] = true; // Page zero stays unavailable, as in the kernel allocator.
    }

    uint64_t* table(uint64_t page) {
        assert(page % page_size == 0);
        const auto index = page / page_size;
        assert(index > 0 && index < memory.size() && owned[index]);
        return memory[index].data();
    }

    uint64_t allocate() {
        if (remaining == 0)
            return 0;
        if (remaining > 0)
            --remaining;
        for (size_t i = 2; i < owned.size(); ++i) {
            if (owned[i])
                continue;
            owned[i] = true;
            memory[i] = {};
            ++pending;
            return i * page_size;
        }
        assert(false);
        return 0;
    }

    void release(uint64_t page) {
        const auto index = page / page_size;
        assert(index > 1 && index < owned.size() && owned[index]);
        // Pages must still be private when a failed transaction releases them.
        for (size_t i = 1; i < memory.size(); ++i)
            if (owned[i] && i != index)
                for (uint64_t entry : memory[i])
                    assert(!(entry & 1) || (entry & page_mask) != page);
        owned[index] = false;
        memory[index] = {};
        --pending;
    }

    uint64_t* entry(uint64_t va, int level, bool create) {
        auto* current = table(page_size);
        for (int shift = 39; shift >= level; shift -= 9) {
            uint64_t& entry = current[(va >> shift) & 511];
            if (shift == level)
                return &entry;
            if (!entry) {
                if (!create)
                    return nullptr;
                entry = allocate() | 3;
            }
            if (!(entry & 1) || (entry & 128))
                return nullptr;
            current = table(entry & page_mask);
        }
        return nullptr;
    }

    bool map(const Range& span, Mmio::CacheLayout cache = normal) {
        const Mmio::PageTables ops{
            this, [](void* c, uint64_t p) { return static_cast<Fixture*>(c)->table(p); },
            [](void* c) { return static_cast<Fixture*>(c)->allocate(); },
            [](void* c, uint64_t p) { static_cast<Fixture*>(c)->release(p); },
            [](void* c, uint64_t va) {
                auto& f = *static_cast<Fixture*>(c);
                auto* leaf = f.entry(va, 12, false);
                assert(leaf && (*leaf & 1)); // Parent tables are already linked when flushed.
                f.flushes.push_back(va);
            }};
        return Mmio::install(span, page_size, limit, cache, ops);
    }
};

void addresses() {
    Range r{};
    assert(!Mmio::range(0x400000, 0, direct, limit, r));
    assert(!Mmio::range(0x400000, 1024 * 1024 + 1, direct, limit, r));
    assert(!Mmio::range(limit, 1, direct, limit, r));
    assert(!Mmio::range(limit - 1, 2, direct, limit, r));
    assert(!Mmio::range(0, 1, direct + 1, limit, r));
    assert(!Mmio::range(0, 1, 0x800000000000ull, limit, r));
    assert(!Mmio::range(page_size, 1, UINT64_MAX - page_size + 1, limit, r));
    assert(Mmio::range(limit - 1, 1, direct, limit, r));
    assert(r.physical_page == limit - page_size && r.pages == 1);
    assert(Mmio::range(page_size + 1, 1024 * 1024, direct, limit, r));
    assert(r.physical_page == page_size && r.virtual_page == direct + page_size && r.pages == 257);

    const uint64_t last_page = UINT64_MAX - page_size + 1;
    assert(Mmio::range(page_size - 1, 1, last_page, limit, r));
    assert(r.virtual_page == last_page && r.pages == 1);
    Fixture edge;
    assert(edge.map(r) && edge.flushes == std::vector<uint64_t>{last_page});
}

void boot_map() {
    constexpr uint64_t base = 0xfc400000;
    using Kind = BootMemoryKind;
    std::array<BootMemory, 4> map{{{base - page_size, page_size, Kind::usable},
                                   {base, page_size, Kind::reserved},
                                   {base + page_size, page_size, Kind::firmware},
                                   {base + 2 * page_size, page_size, Kind::mapped_reserved}}};
    BootInfo boot{};
    boot.memory_context = &map;
    boot.memory_count = map.size();
    boot.memory_at = [](const void* p, size_t i) {
        return (*static_cast<const std::array<BootMemory, 4>*>(p))[i];
    };
    Range r{base, direct + base, 3};
    assert(Mmio::permits(r, boot));
    for (Kind kind : {Kind::usable, Kind::retained, Kind::other}) {
        map[2] = {base + 2 * page_size - 1, 1, kind};
        assert(!Mmio::permits(r, boot));
    }
    map[2] = {base - 1, UINT64_MAX, Kind::retained};
    assert(!Mmio::permits(r, boot));
    map[2] = {base, 0, Kind::retained};
    assert(Mmio::permits(r, boot));
}

void stage_failures() {
    // A two-page request across a PML4 edge needs three private tables on each side.
    const auto edge = direct + (1ull << 39) - page_size;
    const Range r{0x400000, edge, 2};
    for (int allowed = 0; allowed < 6; ++allowed) {
        Fixture f;
        f.remaining = allowed;
        assert(!f.map(r) && !f.pending && f.flushes.empty());
        assert(f.memory[1] == Fixture::Table{});
    }
    Fixture f;
    f.remaining = 6;
    assert(f.map(r) && f.pending == 6 && f.flushes.size() == 2);
    assert(*f.entry(edge, 12, false) == (r.physical_page | uc_page));
    assert(*f.entry(edge + page_size, 12, false) == ((r.physical_page + page_size) | uc_page));

    Fixture conflict;
    auto* tail = conflict.entry(edge + page_size, 12, true);
    *tail = (r.physical_page + page_size) | nx | 3; // Existing writable, cacheable mapping.
    const auto before = conflict.memory;
    assert(!conflict.map(r) && conflict.pending == 3 && conflict.flushes.empty());
    assert(conflict.memory == before);

    Fixture shared;
    const Range same_table{0x810000, direct + 0x810000, 2};
    auto* original = shared.entry(same_table.virtual_page + page_size, 12, true);
    *original = 0x02000000 | uc_page; // Wrong physical address, with valid permissions.
    assert(!shared.map(same_table) && shared.flushes.empty());
    assert(!*shared.entry(same_table.virtual_page, 12, false));
    assert(*original == (0x02000000 | uc_page));
}

void cache_and_permissions() {
    const Range r{0xfc200000, direct + 0xfc200000, 1};
    auto va = r.virtual_page;
    // Hardware A/D state and accepted uncached aliases stay untouched.
    Fixture f;
    auto* leaf = f.entry(va, 12, true);
    *leaf = r.physical_page | uc_page | (3 << 5) | (1 << 8);
    auto old = *leaf;
    assert(f.map(r) && *leaf == old && f.flushes.empty());

    const uint64_t conflicts[]{nx | 0x13, uc_page | 4, uc_page & ~nx, uc_page & ~2ull, 0x200};
    for (uint64_t flags : conflicts) {
        old = r.physical_page | flags;
        *leaf = old;
        assert(!f.map(r) && *leaf == old && f.flushes.empty());
    }

    Fixture parent;
    auto* pde = parent.entry(va, 21, true);
    *pde = 0xfc200000 | uc_page | 128;
    old = *pde;
    assert(!parent.map(r) && *pde == old && parent.pending == 2);
    auto* pml4 = parent.entry(va, 39, false);
    *pml4 &= ~2ull;
    old = *pml4;
    assert(!parent.map(r) && *pml4 == old && parent.pending == 2);

    Fixture changed_pat;
    const Mmio::CacheLayout only_slot_five{0x0606000606060606ull, true};
    assert(changed_pat.map(r, only_slot_five));
    assert(*changed_pat.entry(va, 12, false) == (r.physical_page | nx | 0x8b));
    assert(changed_pat.map(r, only_slot_five) && changed_pat.flushes.size() == 1);

    Fixture legacy;
    assert(legacy.map(r, {normal.types, false}));
    assert(*legacy.entry(va, 12, false) == (r.physical_page | uc_page));

    Fixture no_uncached;
    assert(!no_uncached.map(r, {0x0606060606060606ull, true}));
    assert(!no_uncached.pending && no_uncached.flushes.empty());
}
} // namespace

int main() {
    addresses();
    boot_map();
    stage_failures();
    cache_and_permissions();
    std::puts("MMIO_PASS address_limits boot_reservations six_allocation_faults late_conflicts "
              "cache permissions");
}

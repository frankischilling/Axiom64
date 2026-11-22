// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/mm/mmio.hpp
 * @brief   Declares bounded x86 MMIO page-table mapping.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Defines address admission, cache selection, and the page-table provider.
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
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax {
struct BootInfo;

namespace Mmio {
constexpr uint64_t leaf_cache_mask = (1ull << 3) | (1ull << 4) | (1ull << 7);

struct Range {
    uint64_t physical_page;
    uint64_t virtual_page;
    size_t pages;
};

struct CacheLayout {
    uint64_t types;
    bool pat;
};

struct PageTables {
    void* context;
    uint64_t* (*table)(void*, uint64_t);
    uint64_t (*allocate)(void*);
    void (*release)(void*, uint64_t);
    void (*invalidate)(void*, uint64_t);
};

bool range(uint64_t address, size_t length, uint64_t direct, uint64_t physical_limit, Range& out);
bool permits(const Range&, const BootInfo&);
bool install(const Range&, uint64_t root, uint64_t physical_limit, CacheLayout, const PageTables&);
bool alias_cache_flags(const Range&, uint64_t root, uint64_t physical_limit, const PageTables&,
                       uint64_t& flags);
} // namespace Mmio
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/cache.hpp
 * @brief   Read-through buffer cache for a claimed block volume.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Stores clean blocks in four-way sets indexed relative to their volume.
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
#include "drivers/block/block.hpp"

namespace ax {
class BlockCache {
  public:
    static constexpr unsigned ways = 4, max_sectors = 8;

    static size_t sets_for_budget(unsigned sectors, uint64_t budget);
    bool initialize(unsigned sectors, size_t sets);
    void destroy();
    uint64_t maximum_bytes() const;
    uint64_t allocated_bytes() const;
    size_t growth_bytes() const;
    bool read(uint64_t sector, void* data, size_t count);
    void remember(uint64_t sector, const void* data, size_t count, bool allow_growth);
    void invalidate(uint64_t sector, size_t count);

  private:
    static constexpr size_t metadata_overhead = 3 * page_size;
    static constexpr size_t sets_per_slab = 4;

    struct Entry {
        uint64_t tag, recency;
    };

    struct Set {
        uint8_t* data;
        Entry entries[ways];
    };

    static size_t slab_budget(unsigned sectors);
    bool cacheable(uint64_t sector, size_t count) const;

    unsigned sectors_, shift_;
    size_t set_count_, resident_slabs_;
    uint64_t access_;
    Set* sets_;
};
} // namespace ax

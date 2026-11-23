// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/block/cache.cpp
 * @brief   Block buffer lookup and write invalidation.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Caches complete aligned reads and invalidates every entry touched by a write.
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
#include "drivers/block/cache.hpp"

namespace ax {
size_t BlockCache::slab_budget(unsigned sectors) {
    // The allocation header may require another page when the data fills a page.
    return align_up(sets_per_slab * ways * sectors * sector_size + 1);
}

size_t BlockCache::sets_for_budget(unsigned sectors, uint64_t budget) {
    const size_t cost = sets_per_slab * sizeof(Set) + slab_budget(sectors);
    return budget > metadata_overhead ? (budget - metadata_overhead) / cost * sets_per_slab : 0;
}

bool BlockCache::initialize(unsigned sectors, size_t sets) {
    if (!sectors || sectors > max_sectors || (sectors & (sectors - 1)) || !sets ||
        sets % sets_per_slab || sets > SIZE_MAX / sizeof(Set))
        return false;
    sets_ = static_cast<Set*>(alloc(sets * sizeof(Set)));
    if (!sets_)
        return false;
    memset(sets_, 0, sets * sizeof(Set));
    sectors_ = sectors;
    shift_ = __builtin_ctz(sectors);
    set_count_ = sets;
    resident_slabs_ = 0;
    access_ = 0;
    return true;
}

void BlockCache::destroy() {
    for (size_t i = 0; i < set_count_; i += sets_per_slab)
        release(sets_[i].data);
    release(sets_);
}

uint64_t BlockCache::maximum_bytes() const {
    return metadata_overhead + set_count_ * sizeof(Set) +
           (set_count_ / sets_per_slab) * growth_bytes();
}

uint64_t BlockCache::allocated_bytes() const {
    return metadata_overhead + set_count_ * sizeof(Set) + resident_slabs_ * growth_bytes();
}

size_t BlockCache::growth_bytes() const {
    return slab_budget(sectors_);
}

bool BlockCache::cacheable(uint64_t sector, size_t count) const {
    return count == sectors_ && sector != UINT64_MAX && !(sector & (sectors_ - 1));
}

bool BlockCache::read(uint64_t sector, void* data, size_t count) {
    if (!cacheable(sector, count))
        return false;
    const auto block = sector >> shift_;
    auto& set = sets_[block % set_count_];
    for (unsigned way = 0; way < ways; ++way)
        if (set.entries[way].tag == block + 1) {
            memcpy(data, set.data + way * count * sector_size, count * sector_size);
            set.entries[way].recency = ++access_;
            return true;
        }
    return false;
}

void BlockCache::remember(uint64_t sector, const void* data, size_t count, bool allow_growth) {
    if (!cacheable(sector, count))
        return;
    const auto block = sector >> shift_;
    const auto index = block % set_count_;
    auto& set = sets_[index];
    const size_t length = count * sector_size;
    if (!set.data) {
        if (!allow_growth)
            return;
        const size_t set_size = ways * length;
        auto data_slab = static_cast<uint8_t*>(alloc(sets_per_slab * set_size));
        if (!data_slab)
            return;
        const auto first = index - index % sets_per_slab;
        for (size_t i = 0; i < sets_per_slab; ++i)
            sets_[first + i].data = data_slab + i * set_size;
        ++resident_slabs_;
    }
    unsigned victim = 0;
    for (unsigned way = 0; way < ways; ++way) {
        if (set.entries[way].tag == block + 1) {
            victim = way;
            break;
        }
        if (set.entries[way].recency < set.entries[victim].recency)
            victim = way;
    }
    memcpy(set.data + victim * length, data, length);
    set.entries[victim] = {block + 1, ++access_};
}

void BlockCache::invalidate(uint64_t sector, size_t count) {
    if (!count)
        return;
    const uint64_t first = sector >> shift_;
    const uint64_t last = (sector + min(count - 1, UINT64_MAX - sector)) >> shift_;
    if (last - first >= set_count_) {
        for (size_t i = 0; i < set_count_; ++i)
            for (auto& entry : sets_[i].entries)
                if (entry.tag && entry.tag - 1 >= first && entry.tag - 1 <= last)
                    entry = {};
        return;
    }
    for (uint64_t i = 0; i <= last - first; ++i)
        for (auto& entry : sets_[(first + i) % set_count_].entries)
            if (entry.tag == first + i + 1)
                entry = {};
}
} // namespace ax

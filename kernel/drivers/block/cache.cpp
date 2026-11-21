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
void BlockCache::initialize(unsigned sectors) {
    sectors_ = sectors;
    shift_ = __builtin_ctz(sectors);
    memset(tags_, 0, sizeof(tags_));
}

bool BlockCache::cacheable(uint64_t sector, size_t count) const {
    return count == sectors_ && !(sector & (sectors_ - 1));
}

bool BlockCache::read(uint64_t sector, void* data, size_t count) const {
    if (!cacheable(sector, count))
        return false;
    uint64_t block = sector >> shift_, slot = block % slots;
    if (tags_[slot] != block + 1)
        return false;
    memcpy(data, data_[slot], count * sector_size);
    return true;
}

void BlockCache::remember(uint64_t sector, const void* data, size_t count) {
    if (!cacheable(sector, count))
        return;
    uint64_t block = sector >> shift_, slot = block % slots;
    memcpy(data_[slot], data, count * sector_size);
    tags_[slot] = block + 1;
}

void BlockCache::invalidate(uint64_t sector, size_t count) {
    if (!count)
        return;
    uint64_t first = sector >> shift_, last = (sector + count - 1) >> shift_;
    if (last - first >= slots - 1) {
        memset(tags_, 0, sizeof(tags_));
        return;
    }
    for (uint64_t block = first; block <= last; block++) {
        auto& tag = tags_[block % slots];
        if (tag == block + 1)
            tag = 0;
    }
}
} // namespace ax

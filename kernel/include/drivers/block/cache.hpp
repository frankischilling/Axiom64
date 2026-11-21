// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/cache.hpp
 * @brief   Read-through buffer cache for a claimed block volume.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Declares fixed-size cache entries indexed by sectors relative to their volume.
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
    static constexpr unsigned slots = 128, max_sectors = 8;

    void initialize(unsigned sectors);
    bool read(uint64_t sector, void* data, size_t count) const;
    void remember(uint64_t sector, const void* data, size_t count);
    void invalidate(uint64_t sector, size_t count);

  private:
    bool cacheable(uint64_t sector, size_t count) const;

    unsigned sectors_, shift_;
    uint64_t tags_[slots];
    uint8_t data_[slots][max_sectors * sector_size];
};
} // namespace ax

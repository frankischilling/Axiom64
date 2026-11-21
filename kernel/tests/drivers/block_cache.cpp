// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/drivers/block_cache.cpp
 * @brief   Host tests for the block buffer cache.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Exercises aligned hits, collisions and invalidation of partial and multi-block writes.
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
#include <assert.h>

using namespace ax;

int main() {
    BlockCache cache;
    cache.initialize(8);
    uint8_t pattern[4096], output[4096];
    memset(pattern, 0x51, sizeof(pattern));
    memset(output, 0x7c, sizeof(output));
    assert(!cache.read(0, output, 8) && output[0] == 0x7c);
    cache.remember(0, pattern, 8);
    assert(cache.read(0, output, 8));
    assert(!memcmp(output, pattern, sizeof(output)));
    assert(!cache.read(0, output, 4) && !cache.read(1, output, 8));
    cache.remember(1, output, 8);
    assert(!cache.read(1, output, 8));

    cache.remember(8, pattern, 8);
    cache.remember(16, pattern, 8);
    cache.invalidate(7, 2);
    assert(!cache.read(0, output, 8) && !cache.read(8, output, 8));
    assert(cache.read(16, output, 8));
    cache.invalidate(16, 0);
    assert(cache.read(16, output, 8));

    uint64_t collision = 16 + 8 * BlockCache::slots;
    memset(pattern, 0xa4, sizeof(pattern));
    cache.remember(collision, pattern, 8);
    cache.invalidate(16, 8);
    assert(!cache.read(16, output, 8) && cache.read(collision, output, 8));
    assert(!memcmp(output, pattern, sizeof(output)));

    cache.invalidate(1, 16 * BlockCache::slots);
    assert(!cache.read(collision, output, 8));
    BlockCache small;
    small.initialize(2);
    small.remember(2, pattern, 2);
    assert(small.read(2, output, 2) && !memcmp(output, pattern, 1024));
    small.invalidate(3, 1);
    assert(!small.read(2, output, 2));
}

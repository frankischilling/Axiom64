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
#include <cstdlib>

using namespace ax;

static bool deny_allocation;

void* ax::alloc(size_t size) {
    return deny_allocation ? nullptr : std::malloc(size);
}

void ax::release(void* storage) {
    std::free(storage);
}

int main() {
    BlockCache cache;
    constexpr size_t sets = 8;
    assert(cache.initialize(8, sets));
    uint8_t pattern[4096], output[4096];
    memset(pattern, 0x51, sizeof(pattern));
    memset(output, 0x7c, sizeof(output));
    assert(!cache.read(0, output, 8) && output[0] == 0x7c);
    auto metadata = cache.allocated_bytes();
    deny_allocation = true;
    cache.remember(0, pattern, 8, true);
    deny_allocation = false;
    cache.remember(0, pattern, 8, false);
    assert(!cache.read(0, output, 8) && cache.allocated_bytes() == metadata);
    cache.remember(0, pattern, 8, true);
    assert(cache.allocated_bytes() == metadata + cache.growth_bytes());
    assert(cache.read(0, output, 8));
    assert(!memcmp(output, pattern, sizeof(output)));
    assert(!cache.read(0, output, 4) && !cache.read(1, output, 8));
    cache.remember(1, output, 8, true);
    assert(!cache.read(1, output, 8));

    cache.remember(8, pattern, 8, true);
    cache.remember(16, pattern, 8, true);
    cache.invalidate(7, 2);
    assert(!cache.read(0, output, 8) && !cache.read(8, output, 8));
    assert(cache.read(16, output, 8));
    cache.invalidate(16, 0);
    assert(cache.read(16, output, 8));

    constexpr uint64_t stride = 8 * sets;
    const auto resident = cache.allocated_bytes();
    memset(pattern, 0xa4, sizeof(pattern));
    for (unsigned way = 1; way < BlockCache::ways; ++way)
        cache.remember(16 + way * stride, pattern, 8, false);
    assert(cache.read(16, output, 8));
    const uint64_t collision = 16 + BlockCache::ways * stride;
    cache.remember(collision, pattern, 8, false);
    assert(cache.allocated_bytes() == resident);
    assert(!cache.read(16 + stride, output, 8));
    assert(cache.read(16, output, 8) && cache.read(collision, output, 8));
    assert(!memcmp(output, pattern, sizeof(output)));

    cache.invalidate(7, collision - 7);
    assert(!cache.read(16, output, 8) && cache.read(collision, output, 8));
    cache.invalidate(0, 16 * stride);
    assert(!cache.read(collision, output, 8));
    cache.destroy();

    BlockCache small;
    assert(small.initialize(2, sets));
    small.remember(2, pattern, 2, true);
    assert(small.read(2, output, 2) && !memcmp(output, pattern, 1024));
    small.invalidate(3, 1);
    assert(!small.read(2, output, 2));
    small.destroy();

    constexpr uint64_t budget = 8 * 1024 * 1024;
    BlockCache sized;
    assert(sized.initialize(8, BlockCache::sets_for_budget(8, budget)));
    assert(sized.maximum_bytes() <= budget && sized.allocated_bytes() < budget / 8);
    sized.destroy();
}

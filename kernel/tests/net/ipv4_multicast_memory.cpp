// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/net/ipv4_multicast_memory.cpp
 * @brief   IPv4 multicast resource tests.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks resource ownership as multicast state is allocated, reused, and
 * released.
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
#include "ipv4_multicast_memory.hpp"
#include <cassert>
#include <cstdlib>
#include <cstdint>

namespace {
unsigned remaining = UINT32_MAX;
size_t live = 0;
} // namespace

namespace multicast_test {
void allocation_limit(unsigned successful_allocations) {
    remaining = successful_allocations;
}

size_t live_allocations() {
    return live;
}
} // namespace multicast_test

namespace ax {
void* alloc(size_t size) {
    if (!remaining)
        return nullptr;
    void* result = std::malloc(size);
    if (result) {
        live++;
        if (remaining != UINT32_MAX)
            remaining--;
    }
    return result;
}

void release(void* memory) {
    if (!memory)
        return;
    assert(live);
    live--;
    std::free(memory);
}
} // namespace ax

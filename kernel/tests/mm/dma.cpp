// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/mm/dma.cpp
 * @brief   Direct DMA allocation tests.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Compares bitmap selection with a page-by-page oracle and tests bus address limits.
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
#include <cassert>
#include <cstdio>
#include "mm/dma.hpp"

namespace {
using namespace ax;

bool free_window(uint32_t used, size_t page, size_t count, size_t ceiling, size_t boundary) {
    if (count > ceiling - page || (boundary && page / boundary != (page + count - 1) / boundary))
        return false;
    for (size_t p = page; p < page + count; ++p)
        if (used & (1u << p))
            return false;
    return true;
}

size_t expected(uint32_t used, size_t ceiling, size_t cursor, size_t count, size_t boundary) {
    for (size_t page = max(cursor, size_t(1)); page < ceiling; ++page)
        if (free_window(used, page, count, ceiling, boundary))
            return page;
    for (size_t page = 1; page < min(cursor, ceiling); ++page)
        if (free_window(used, page, count, ceiling, boundary))
            return page;
    return 0;
}

void check_selector() {
    constexpr size_t frame_count = 32;
    const uint8_t hole[]{0xff, 0xf1};
    assert(Dma::find_free_run(hole, 16, 10, 3, 0) == 9); // Run spans the cursor.
    assert(Dma::find_free_run(hole, 11, 10, 3, 0) == 0);
    assert(Dma::find_free_run(hole, 16, 0, 0, 0) == 0);
    assert(Dma::find_free_run(hole, 16, 0, 1, 3) == 0);
    const uint8_t empty[4]{};
    assert(Dma::find_free_run(empty, 32, 15, 3, 16) == 16);
    assert(Dma::find_free_run(empty, 32, 14, 2, 16) == 14);
    assert(Dma::find_free_run(empty, 32, 0, 17, 16) == 0);
    assert(Dma::find_free_run(empty, 32, 0, 1, 0) == 1);

    uint32_t used = 0;
    const size_t boundaries[]{0, 2, 4, 8, 16};
    for (unsigned sample = 0; sample < 128; ++sample) {
        uint8_t bitmap[4]{};
        for (unsigned byte = 0; byte < sizeof(bitmap); ++byte)
            bitmap[byte] = uint8_t(used >> (8 * byte));
        for (size_t ceiling = 1; ceiling <= frame_count; ++ceiling)
            for (size_t cursor = 0; cursor <= frame_count + 1; ++cursor)
                for (size_t boundary : boundaries)
                    for (size_t count = 1; count <= 8; ++count)
                        assert(Dma::find_free_run(bitmap, ceiling, cursor, count, boundary) ==
                               expected(used, ceiling, cursor, count, boundary));
        used = used * 1664525u + 1013904223u;
    }
}

void check_apertures() {
    constexpr Dma::Limits isa{1u << 24, 1u << 16};
    assert(Dma::fits(0xfff000, page_size, isa));
    assert(!Dma::fits(0xfff000, page_size + 1, isa));
    assert(Dma::fits(0xfeff00, 256, isa));
    assert(!Dma::fits(0xfeff00, 257, isa));
    assert(!Dma::fits(UINT64_MAX, 1, isa));
    assert(!Dma::fits(0, page_size, {1u << 24, 3}));
    assert(Dma::fits(Dma::pci.end - 1, 1, Dma::pci));
    assert(!Dma::fits(Dma::pci.end - 1, 2, Dma::pci));
    assert(!Dma::fits(Dma::pci.end - 1, SIZE_MAX, Dma::pci));
    assert(!Dma::fits(Dma::pci.end, 0, Dma::pci));
}
} // namespace

int main() {
    check_selector();
    check_apertures();
    std::puts("DMA_PASS bitmap_oracle cursor_wrap ISA_24bit_64KiB PCI_32bit");
}

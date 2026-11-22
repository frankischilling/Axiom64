// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/mm/dma.cpp
 * @brief   Contiguous physical page selection.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Finds a free run inside the aperture and any required DMA boundary.
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
#include "mm/dma.hpp"

namespace ax::Dma {
static size_t scan(const uint8_t* bitmap, size_t first, size_t ceiling, size_t count,
                   size_t boundary_pages, size_t first_pfn) {
    size_t run = 0;
    for (size_t p = first; p < ceiling; ++p) {
        if (boundary_pages && !((first_pfn + p) & (boundary_pages - 1)))
            run = 0;
        run = bitmap[p / 8] & (1u << (p % 8)) ? 0 : run + 1;
        if (run == count)
            return p - count + 1;
    }
    return 0;
}

size_t find_free_run(const uint8_t* bitmap, size_t ceiling, size_t cursor, size_t count,
                     size_t boundary_pages, size_t first_pfn) {
    if (!count || ceiling <= count ||
        (boundary_pages && (!power_of_two(boundary_pages) || count > boundary_pages)))
        return 0;
    cursor = max(cursor, size_t(1));
    if (cursor < ceiling && count <= ceiling - cursor) {
        const auto start = scan(bitmap, cursor, ceiling, count, boundary_pages, first_pfn);
        if (start)
            return start;
    }
    // A run starting before the cursor can extend past it.
    return cursor == 1 ? 0 : scan(bitmap, 1, ceiling, count, boundary_pages, first_pfn);
}
} // namespace ax::Dma

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/mm/dma.hpp
 * @brief   Address limits for direct DMA.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Defines the aperture and boundary checks shared by drivers and the allocator.
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
#include "core/base.hpp"

namespace ax::Dma {
struct Limits {
    uint64_t end; // Exclusive upper byte address.
    uint64_t boundary = 0;
};

// Keep current PCI buffers addressable by devices with 32-bit DMA.
inline constexpr Limits pci{1ull << 32};

constexpr bool power_of_two(uint64_t value) {
    return value && !(value & (value - 1));
}

constexpr bool fits(uint64_t address, size_t bytes, Limits limits) {
    if (address >= limits.end || bytes > limits.end - address)
        return false;
    return !limits.boundary || (power_of_two(limits.boundary) &&
                                bytes <= limits.boundary - (address & (limits.boundary - 1)));
}

// Return contiguous, zeroed pages. The caller must stop DMA before page_free.
uint64_t allocate(size_t pages, Limits limits);

// Read the allocator's used-page bitmap. Page zero is never returned.
size_t find_free_run(const uint8_t* bitmap, size_t ceiling, size_t cursor, size_t count,
                     size_t boundary_pages);
} // namespace ax::Dma

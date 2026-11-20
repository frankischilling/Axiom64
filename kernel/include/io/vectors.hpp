// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/io/vectors.hpp
 * @brief   Userspace I/O vector interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines imported I/O vector state and helpers to validate and advance a
 * transfer.
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

namespace ax {
struct IoVector {
    uint64_t base, length;
};

static_assert(sizeof(IoVector) == 16);

// Operate on captured metadata, never on a caller's mutable vector array.
inline int64_t bound_io_vectors(IoVector* vectors, size_t count) {
    for (size_t n = 0; n < count; n++) {
        if (vectors[n].length > uint64_t(INT64_MAX))
            return -22;
    }
    size_t capacity = 0;
    for (size_t n = 0; n < count; n++) {
        auto& vector = vectors[n];
        // A single vector uses Linux's UBUF clamp before checking its span.
        // Multiple vectors validate every full span before clipping the total.
        if (count == 1)
            vector.length = min(vector.length, uint64_t(0x7ffff000));
        if (vector.base > user_limit || vector.length > user_limit - vector.base)
            return -14;
        vector.length = min(vector.length, uint64_t(0x7ffff000 - capacity));
        capacity += vector.length;
    }
    return capacity;
}
} // namespace ax

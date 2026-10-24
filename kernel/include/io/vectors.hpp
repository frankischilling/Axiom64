// SPDX-License-Identifier: GPL-3.0-or-later
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

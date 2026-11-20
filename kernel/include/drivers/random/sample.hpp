// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/random/sample.hpp
 * @brief   Hardware entropy sampling interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the platform random-source collection interface used during
 * initialization and runtime.
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
#include "core/random/primitives.hpp"

namespace ax {
// One writable request at a time. Short responses accumulate within one two-second deadline.
class EntropyRequest {
    uint8_t bytes_[32]{};
    uint64_t cookie_ = 0, deadline_ = 0;
    uint16_t head_ = 0;
    unsigned filled_ = 0, consumed_ = 0;
    bool pending_ = false;

  public:
    unsigned remaining() const {
        return sizeof(bytes_) - filled_;
    }

    unsigned accumulated() const {
        return filled_;
    }

    bool pending() const {
        return pending_;
    }

    bool expired(uint64_t now) const {
        return (pending_ || filled_) && now >= deadline_;
    }

    bool begin(uint64_t cookie, uint16_t head, uint64_t now);
    int complete(uint64_t cookie, uint16_t head, const void* data, unsigned length);
    void reset();
    static bool word(void*, uint64_t&);
};
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/core/random/primitives.hpp
 * @brief   Random engine cryptographic primitives.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the low-level hashing and stream primitives used by the random
 * engine.
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
#include <stddef.h>
#include <stdint.h>

namespace ax::random {
void erase(void*, size_t);
void chacha20_block(uint8_t output[64], const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12]);

class Blake2s {
    uint32_t state_[8];
    uint8_t block_[64]{};
    uint64_t count_ = 0;
    size_t used_ = 0;
    void compress(bool final);

  public:
    Blake2s();
    void update(const void*, size_t);
    void finish(uint8_t output[32]); // Consumes and erases this context.
};
} // namespace ax::random

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/core/random/engine.hpp
 * @brief   Random engine state.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines seeded generator state and the operations used to collect, generate,
 * and erase random material.
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

namespace ax::random {
// Internal pool/generator seam: the x86 adapter and deterministic fixtures share it.
class Generator {
    uint8_t pool_[32]{}, key_[32]{};
    unsigned initialization_bits_ = 0;
    void rekey();

  public:
    Generator() = default;
    Generator(const Generator&) = delete;
    Generator& operator=(const Generator&) = delete;

    bool ready() const {
        return initialization_bits_ == 256;
    }

    unsigned entropy_count() const {
        return initialization_bits_;
    }

    void mix(const void*, size_t);        // Never credits entropy, including user writes.
    void seed(const uint8_t trusted[32]); // Only the validated trusted-source adapter calls this.
    void credit(unsigned bits);           // Trusted-source or privileged administrator assertion.
    int reseed();                         // Re-extract the pool; -ENODATA before initialization.
    int read(void*, size_t, bool insecure = false); // 0 or negative errno; no partial output.
};

class SeedSource {
    bool available_;
    bool (*word_)(void*, uint64_t&);
    void* context_;
    uint64_t previous_ = 0;
    bool seen_ = false;

  public:
    constexpr SeedSource(bool available, bool (*word)(void*, uint64_t&), void* context = nullptr)
        : available_(available), word_(word), context_(context) {
    }

    bool seed(Generator&); // At most 40 instruction attempts; failed samples are erased.
    bool feed(Generator&, bool trusted); // Validated but untrusted samples only mix.
};
} // namespace ax::random

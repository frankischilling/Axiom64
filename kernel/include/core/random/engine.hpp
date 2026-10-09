// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/random/primitives.hpp"

namespace ax::random {
// Internal pool/generator seam: the x86 adapter and deterministic fixtures share it.
class Generator {
    uint8_t pool_[32]{}, key_[32]{};
    bool ready_ = false;
    void rekey();

  public:
    Generator() = default;
    Generator(const Generator&) = delete;
    Generator& operator=(const Generator&) = delete;

    bool ready() const {
        return ready_;
    }

    void mix(const void*, size_t);        // Never credits entropy, including user writes.
    void seed(const uint8_t trusted[32]); // Only the validated trusted-source adapter calls this.
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
};
} // namespace ax::random

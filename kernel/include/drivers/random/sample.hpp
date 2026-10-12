// SPDX-License-Identifier: GPL-3.0-or-later
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

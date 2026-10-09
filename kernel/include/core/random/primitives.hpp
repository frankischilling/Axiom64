// SPDX-License-Identifier: GPL-3.0-or-later
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

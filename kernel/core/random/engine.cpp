// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/random/engine.hpp"

namespace ax::random {
void Generator::rekey() {
    Blake2s extract;
    extract.update("AX64key1", 8);
    extract.update(key_, sizeof(key_));
    extract.update(pool_, sizeof(pool_));
    extract.finish(key_);
    // Advance the pool after extraction so later pool disclosure cannot reproduce old keys.
    Blake2s advance;
    advance.update("AX64adv1", 8);
    advance.update(pool_, sizeof(pool_));
    advance.update(key_, sizeof(key_));
    advance.finish(pool_);
}

void Generator::mix(const void* data, size_t size) {
    if (!size)
        return;
    Blake2s pool;
    pool.update("AX64mix1", 8);
    pool.update(pool_, sizeof(pool_));
    pool.update(data, size);
    pool.finish(pool_);
    rekey();
}

void Generator::seed(const uint8_t trusted[32]) {
    mix(trusted, 32);
    ready_ = true;
}

int Generator::read(void* data, size_t size, bool insecure) {
    if (!ready_ && !insecure)
        return -11;
    auto bytes = static_cast<uint8_t*>(data);
    while (size) {
        uint8_t block[64], nonce[12]{};
        chacha20_block(block, key_, 0, nonce);
        // The first half becomes the next key and is never returned. Discard unused output.
        for (unsigned i = 0; i < 32; i++)
            key_[i] = block[i];
        size_t count = size < 32 ? size : 32;
        for (size_t i = 0; i < count; i++)
            bytes[i] = block[32 + i];
        erase(block, sizeof(block));
        bytes += count;
        size -= count;
    }
    return 0;
}

bool SeedSource::seed(Generator& generator) {
    if (!available_ || !word_)
        return false;
    uint64_t words[4]{};
    bool accepted = true;
    for (unsigned i = 0; accepted && i < 4; i++) {
        bool supplied = false;
        for (unsigned attempt = 0; attempt < 10 && !supplied; attempt++)
            supplied = word_(context_, words[i]);
        accepted =
            supplied && words[i] && words[i] != UINT64_MAX && (!seen_ || words[i] != previous_);
        for (unsigned earlier = 0; earlier < i; earlier++)
            accepted &= words[i] != words[earlier];
    }
    if (accepted) {
        uint8_t seed[32];
        for (unsigned i = 0; i < 32; i++)
            seed[i] = words[i / 8] >> ((i % 8) * 8);
        previous_ = words[3];
        seen_ = true;
        generator.seed(seed);
        erase(seed, sizeof(seed));
    }
    erase(words, sizeof(words));
    return accepted;
}
} // namespace ax::random

// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/random/primitives.hpp"

namespace ax::random {
void erase(void* data, size_t size) {
    auto bytes = static_cast<volatile uint8_t*>(data);
    while (size--)
        *bytes++ = 0;
}

static uint32_t load(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8 | uint32_t(bytes[2]) << 16 |
           uint32_t(bytes[3]) << 24;
}

static void store(uint8_t* bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++)
        bytes[i] = value >> (8 * i);
}

static uint32_t left(uint32_t value, unsigned count) {
    return value << count | value >> (32 - count);
}

static uint32_t right(uint32_t value, unsigned count) {
    return value >> count | value << (32 - count);
}

static void quarter(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b;
    d = left(d ^ a, 16);
    c += d;
    b = left(b ^ c, 12);
    a += b;
    d = left(d ^ a, 8);
    c += d;
    b = left(b ^ c, 7);
}

void chacha20_block(uint8_t output[64], const uint8_t key[32], uint32_t counter,
                    const uint8_t nonce[12]) {
    uint32_t initial[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (unsigned i = 0; i < 8; i++)
        initial[i + 4] = load(key + 4 * i);
    initial[12] = counter;
    for (unsigned i = 0; i < 3; i++)
        initial[i + 13] = load(nonce + 4 * i);
    uint32_t work[16];
    for (unsigned i = 0; i < 16; i++)
        work[i] = initial[i];
    for (unsigned i = 0; i < 10; i++) {
        quarter(work[0], work[4], work[8], work[12]);
        quarter(work[1], work[5], work[9], work[13]);
        quarter(work[2], work[6], work[10], work[14]);
        quarter(work[3], work[7], work[11], work[15]);
        quarter(work[0], work[5], work[10], work[15]);
        quarter(work[1], work[6], work[11], work[12]);
        quarter(work[2], work[7], work[8], work[13]);
        quarter(work[3], work[4], work[9], work[14]);
    }
    for (unsigned i = 0; i < 16; i++)
        store(output + 4 * i, work[i] + initial[i]);
    erase(initial, sizeof(initial));
    erase(work, sizeof(work));
}

static constexpr uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
static constexpr uint8_t order[10][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
                                          {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
                                          {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
                                          {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
                                          {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
                                          {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
                                          {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
                                          {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
                                          {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
                                          {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

static void mix(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t x, uint32_t y) {
    a += b + x;
    d = right(d ^ a, 16);
    c += d;
    b = right(b ^ c, 12);
    a += b + y;
    d = right(d ^ a, 8);
    c += d;
    b = right(b ^ c, 7);
}

Blake2s::Blake2s() {
    for (unsigned i = 0; i < 8; i++)
        state_[i] = iv[i];
    state_[0] ^= 0x01010020; // Sequential, unkeyed BLAKE2s with a 32-byte digest.
}

void Blake2s::compress(bool final) {
    uint32_t work[16], message[16];
    for (unsigned i = 0; i < 8; i++) {
        work[i] = state_[i];
        work[i + 8] = iv[i];
    }
    work[12] ^= uint32_t(count_);
    work[13] ^= uint32_t(count_ >> 32);
    if (final)
        work[14] = ~work[14];
    for (unsigned i = 0; i < 16; i++)
        message[i] = load(block_ + 4 * i);
    for (const auto& row : order) {
        mix(work[0], work[4], work[8], work[12], message[row[0]], message[row[1]]);
        mix(work[1], work[5], work[9], work[13], message[row[2]], message[row[3]]);
        mix(work[2], work[6], work[10], work[14], message[row[4]], message[row[5]]);
        mix(work[3], work[7], work[11], work[15], message[row[6]], message[row[7]]);
        mix(work[0], work[5], work[10], work[15], message[row[8]], message[row[9]]);
        mix(work[1], work[6], work[11], work[12], message[row[10]], message[row[11]]);
        mix(work[2], work[7], work[8], work[13], message[row[12]], message[row[13]]);
        mix(work[3], work[4], work[9], work[14], message[row[14]], message[row[15]]);
    }
    for (unsigned i = 0; i < 8; i++)
        state_[i] ^= work[i] ^ work[i + 8];
    erase(work, sizeof(work));
    erase(message, sizeof(message));
}

void Blake2s::update(const void* data, size_t size) {
    auto bytes = static_cast<const uint8_t*>(data);
    while (size) {
        if (used_ == sizeof(block_)) {
            count_ += used_;
            compress(false);
            used_ = 0;
        }
        size_t count = size < sizeof(block_) - used_ ? size : sizeof(block_) - used_;
        for (size_t i = 0; i < count; i++)
            block_[used_ + i] = bytes[i];
        used_ += count;
        bytes += count;
        size -= count;
    }
}

void Blake2s::finish(uint8_t output[32]) {
    count_ += used_;
    for (size_t i = used_; i < sizeof(block_); i++)
        block_[i] = 0;
    compress(true);
    for (unsigned i = 0; i < 8; i++)
        store(output + 4 * i, state_[i]);
    erase(this, sizeof(*this));
}
} // namespace ax::random

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/directory_hash.cpp
 * @brief   Name hashing for classic directory indexes.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Implements the legacy, half MD4 and TEA hash formats for byte-string names.
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

#include "volume.hpp"

namespace ax::ext2_detail {
namespace {
uint32_t symbol(uint8_t value, bool unsigned_bytes) {
    return unsigned_bytes || value < 128 ? value : uint32_t(int(value) - 256);
}

uint32_t legacy(const uint8_t* name, unsigned length, bool unsigned_bytes) {
    uint32_t next_hash = 0x12a3fe2d, previous = 0x37abe8f9;
    for (unsigned index = 0; index < length; index++) {
        uint32_t value = previous + (next_hash ^ (symbol(name[index], unsigned_bytes) * 7152373));
        previous = next_hash;
        next_hash = value >= 0x80000000 ? value - 0x7fffffff : value;
    }
    return next_hash << 1;
}

void pack(uint32_t* words, unsigned count, const uint8_t* name, unsigned length,
          bool unsigned_bytes) {
    uint32_t padding = length * 0x01010101u;
    for (unsigned index = 0; index < count; index++) {
        uint32_t value = padding;
        for (unsigned i = index * 4; i < min(index * 4 + 4, length); i++)
            value = (value << 8) + symbol(name[i], unsigned_bytes);
        words[index] = value;
    }
}

void tea(uint32_t* state, const uint32_t* words) {
    uint32_t sum = 0, x = state[0], y = state[1];
    for (unsigned round = 0; round != 16; round++) {
        sum += 0x9e3779b9;
        x += ((y << 4) + words[0]) ^ (y + sum) ^ ((y >> 5) + words[1]);
        y += ((x << 4) + words[2]) ^ (x + sum) ^ ((x >> 5) + words[3]);
    }
    state[0] += x;
    state[1] += y;
}

void half_md4(uint32_t* state, const uint32_t* words) {
    constexpr uint8_t order[3][8] = {
        {0, 1, 2, 3, 4, 5, 6, 7}, {1, 3, 5, 7, 0, 2, 4, 6}, {3, 7, 2, 6, 1, 5, 0, 4}};
    constexpr uint8_t shift[3][4] = {{3, 7, 11, 19}, {3, 5, 9, 13}, {3, 9, 11, 15}};
    constexpr uint32_t constant[3] = {0, 0x5a827999, 0x6ed9eba1};
    uint32_t value[4] = {state[0], state[1], state[2], state[3]};
    for (unsigned pass = 0; pass < 3; pass++)
        for (unsigned step = 0; step < 8; step++) {
            unsigned i = (4 - step) & 3;
            uint32_t x = value[(i + 1) & 3], y = value[(i + 2) & 3], z = value[(i + 3) & 3];
            uint32_t mixed = pass == 0   ? ((x & y) | (~x & z))
                             : pass == 1 ? ((x & y) | (x & z) | (y & z))
                                         : (x ^ y ^ z);
            uint32_t sum = value[i] + mixed + words[order[pass][step]] + constant[pass];
            unsigned bits = shift[pass][step & 3];
            value[i] = (sum << bits) | (sum >> (32 - bits));
        }
    for (unsigned i = 0; i < 4; i++)
        state[i] += value[i];
}
} // namespace

uint32_t directory_hash(const uint8_t* name, unsigned length, unsigned version,
                        const uint32_t* seed, bool unsigned_bytes) {
    uint32_t hash;
    if (version == 0) {
        hash = legacy(name, length, unsigned_bytes);
    } else {
        uint32_t state[] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
        if (seed[0] || seed[1] || seed[2] || seed[3])
            memcpy(state, seed, sizeof(state));
        unsigned words = version == 1 ? 8 : 4;
        while (length) {
            uint32_t input[8];
            pack(input, words, name, length, unsigned_bytes);
            if (version == 1)
                half_md4(state, input);
            else
                tea(state, input);
            unsigned consumed = min(length, words * 4);
            length -= consumed;
            name += consumed;
        }
        hash = state[version == 1 ? 1 : 0] & ~1u;
    }
    return hash == 0xfffffffeu ? 0xfffffffcu : hash;
}
} // namespace ax::ext2_detail

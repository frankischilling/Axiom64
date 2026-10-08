// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax::ip4 {
inline uint16_t get16(const uint8_t* bytes) {
    return (uint16_t(bytes[0]) << 8) | bytes[1];
}

inline uint32_t get32(const uint8_t* bytes) {
    return (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) | (uint32_t(bytes[2]) << 8) |
           bytes[3];
}

inline void put16(uint8_t* bytes, uint16_t value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}

inline void put32(uint8_t* bytes, uint32_t value) {
    bytes[0] = value >> 24;
    bytes[1] = value >> 16;
    bytes[2] = value >> 8;
    bytes[3] = value;
}

inline uint16_t checksum(const uint8_t* bytes, size_t length) {
    uint32_t sum = 0;
    while (length >= 2) {
        sum += get16(bytes);
        bytes += 2;
        length -= 2;
    }
    if (length)
        sum += uint32_t(*bytes) << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return uint16_t(~sum);
}

inline bool unicast(uint32_t address) {
    return address && address != UINT32_MAX && (address >> 24) != 0 && (address >> 28) < 14;
}

inline bool mask_valid(uint32_t mask) {
    uint32_t inverse = ~mask;
    return !(inverse & (inverse + 1));
}
} // namespace ax::ip4

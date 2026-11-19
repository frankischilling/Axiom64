// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/tcp/wire_ipv6.cpp
 * @brief   TCP over IPv6 wire format.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Produces and checks TCP segments with IPv6 addressing and pseudo-header
 * checksums.
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
#include "wire_detail.hpp"
#include "net/ipv6/wire.hpp"

namespace ax::tcp {
bool decode(const ip6::Address& source, const ip6::Address& destination, const void* packet,
            size_t length, Segment& output) {
    return packet && length >= 20 && length <= maximum_ipv6_segment_size &&
           !ip6::checksum(source, destination, 6, static_cast<const uint8_t*>(packet), length) &&
           detail::decode(packet, length, output);
}

size_t encode(const ip6::Address& source, const ip6::Address& destination, const Segment& value,
              void* packet, size_t capacity) {
    size_t length = detail::encode(value, packet, capacity, maximum_ipv6_segment_size);
    if (length) {
        auto* bytes = static_cast<uint8_t*>(packet);
        uint16_t checksum = ip6::checksum(source, destination, 6, bytes, length);
        bytes[16] = checksum >> 8;
        bytes[17] = checksum;
    }
    return length;
}
} // namespace ax::tcp

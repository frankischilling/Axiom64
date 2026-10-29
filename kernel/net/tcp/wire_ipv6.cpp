// SPDX-License-Identifier: GPL-3.0-or-later
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

// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/fragmentation.hpp"
#include "net/ipv6/wire.hpp"
#include "core/base.hpp"

namespace ax::ip6 {
FragmentPiece fragment_packet(const uint8_t* packet, size_t available, uint32_t mtu, size_t offset,
                              uint32_t identification, uint8_t* output, size_t capacity,
                              FragmentLayout layout) {
    if (!packet || !output || available < header_size || packet[0] >> 4 != 6 || mtu < minimum_mtu)
        return {};
    size_t payload = size_t(packet[4]) << 8 | packet[5];
    size_t total = header_size + payload;
    if (total > available || offset % 8)
        return {};
    size_t prefix = header_size, previous = 6, at = header_size, last = 6;
    bool routing = false;
    uint8_t protocol = packet[6];
    while (protocol == 0 || protocol == 43 || protocol == 60) {
        if (protocol == 0 && at != header_size)
            return {};
        if (total - at < 8)
            return {};
        size_t length = (size_t(packet[at + 1]) + 1) * 8;
        if (length > total - at)
            return {};
        // Repeat Hop-by-Hop and all headers through the last Routing header.
        // Destination options following that boundary remain fragmentable.
        if (protocol == 0 || protocol == 43) {
            prefix = at + length;
            previous = at;
        }
        routing |= protocol == 43;
        last = at;
        protocol = packet[at];
        at += length;
    }
    if (protocol == 44 || protocol == 50 || protocol == 51)
        return {-95};
    if (layout == FragmentLayout::linux_socket && !routing) {
        prefix = at;
        previous = last;
    }
    size_t fragmentable = total - prefix;
    if (offset > fragmentable || (offset && offset == fragmentable))
        return {};
    if (!offset && total <= mtu) {
        if (capacity < total)
            return {-105};
        memcpy(output, packet, total);
        return {0, total, fragmentable, true};
    }
    if (prefix > mtu || mtu - prefix <= 8)
        return {-90};
    size_t remaining = fragmentable - offset;
    size_t length = min(remaining, size_t(mtu) - prefix - 8);
    if (length < remaining)
        length &= ~size_t(7);
    if (!length || prefix - header_size + 8 + length > 65535)
        return {-90};
    // The first fragment must carry the entire extension chain and upper-layer
    // header. Opaque protocols retain their existing byte-oriented contract.
    size_t upper = protocol == 17 ? 8 : protocol == 58 ? 4 : 0;
    if (!offset && length < at - prefix + min(upper, total - at))
        return {-90};
    if (capacity < prefix + 8 + length)
        return {-105};
    memcpy(output, packet, prefix);
    size_t output_payload = prefix - header_size + 8 + length;
    output[4] = output_payload >> 8;
    output[5] = output_payload;
    output[previous] = 44;
    auto fragment = output + prefix;
    fragment[0] = packet[previous];
    fragment[1] = 0;
    uint16_t flags = uint16_t(offset) | (length < remaining ? 1 : 0);
    fragment[2] = flags >> 8;
    fragment[3] = flags;
    for (unsigned n = 0; n < 4; n++)
        fragment[4 + n] = identification >> (24 - n * 8);
    memcpy(fragment + 8, packet + prefix + offset, length);
    return {0, prefix + 8 + length, length, length == remaining};
}
} // namespace ax::ip6

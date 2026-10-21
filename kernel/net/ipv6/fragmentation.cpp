// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/fragmentation.hpp"
#include "net/ipv6/wire.hpp"
#include "core/base.hpp"

namespace ax::ip6 {
FragmentPiece fragment_packet(const uint8_t* packet, size_t available, uint32_t mtu, size_t offset,
                              uint32_t identification, uint8_t* output, size_t capacity) {
    if (!packet || !output || available < header_size || packet[0] >> 4 != 6 || mtu < minimum_mtu)
        return {};
    size_t payload = size_t(packet[4]) << 8 | packet[5];
    size_t total = header_size + payload;
    if (total > available || offset % 8 || offset > payload || (offset && offset == payload))
        return {};
    auto protocol = packet[6];
    if (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 50 || protocol == 51 ||
        protocol == 60)
        return {-95};
    if (!offset && total <= mtu) {
        if (capacity < total)
            return {-105};
        memcpy(output, packet, total);
        return {0, total, payload, true};
    }
    size_t remaining = payload - offset;
    size_t length = min(remaining, size_t(mtu) - header_size - 8);
    if (length < remaining)
        length &= ~size_t(7);
    if (!length || length > 65535 - 8)
        return {-90};
    if (capacity < header_size + 8 + length)
        return {-105};
    memcpy(output, packet, header_size);
    output[4] = (length + 8) >> 8;
    output[5] = length + 8;
    output[6] = 44;
    auto fragment = output + header_size;
    fragment[0] = protocol;
    fragment[1] = 0;
    uint16_t flags = uint16_t(offset) | (length < remaining ? 1 : 0);
    fragment[2] = flags >> 8;
    fragment[3] = flags;
    for (unsigned n = 0; n < 4; n++)
        fragment[4 + n] = identification >> (24 - n * 8);
    memcpy(fragment + 8, packet + header_size + offset, length);
    return {0, header_size + 8 + length, length, length == remaining};
}
} // namespace ax::ip6

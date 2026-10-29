// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/fragmentation.hpp"
#include "net/ipv4_wire.hpp"
#include "core/base.hpp"

namespace ax::ip4 {
FragmentPiece fragment_packet(const uint8_t* packet, size_t available, size_t mtu, size_t offset,
                              uint8_t* output, size_t capacity) {
    if (!packet || !output || available < 20 || (packet[0] >> 4) != 4 || mtu < 68 || mtu > 65535)
        return {};
    size_t header = size_t(packet[0] & 15) * 4;
    size_t total = get16(packet + 2);
    if (header < 20 || header > available || total < header || total > available ||
        checksum(packet, header))
        return {};
    uint16_t flags = get16(packet + 6);
    size_t payload = total - header;
    size_t original_offset = size_t(flags & 0x1fff) * 8;
    if ((flags & 0x8000) || offset % 8 || offset > payload || (offset && offset == payload) ||
        original_offset + payload > 65535 - header ||
        ((flags & 0x2000) && (!payload || payload % 8)))
        return {};
    for (size_t at = 20; at < header;) {
        uint8_t type = packet[at];
        if (!type)
            break;
        if (type == 1) {
            at++;
            continue;
        }
        if (at + 2 > header || packet[at + 1] < 2 || packet[at + 1] > header - at)
            return {};
        at += packet[at + 1];
    }
    if (!offset && total <= mtu) {
        if (capacity < total)
            return {-105};
        memcpy(output, packet, total);
        return {0, total, payload, true};
    }
    if (flags & 0x4000)
        return {-90};
    size_t remaining = payload - offset;
    size_t length = min(remaining, mtu - header);
    if (length < remaining)
        length &= ~size_t(7);
    if (!length)
        return {-90};
    if (capacity < header + length)
        return {-105};
    memcpy(output, packet, header);
    if (original_offset + offset) {
        // NOP padding retains option alignment while removing options whose
        // copied bit is clear. The original header and its options stay owned.
        for (size_t at = 20; at < header;) {
            uint8_t type = output[at];
            if (!type)
                break;
            size_t size = type == 1 ? 1 : output[at + 1];
            if (!(type & 0x80))
                memset(output + at, 1, size);
            at += size;
        }
    }
    memcpy(output + header, packet + header + offset, length);
    bool complete = length == remaining;
    put16(output + 2, header + length);
    put16(output + 6, uint16_t((original_offset + offset) / 8) |
                          ((!complete || (flags & 0x2000)) ? 0x2000 : 0));
    put16(output + 10, 0);
    put16(output + 10, checksum(output, header));
    return {0, header + length, length, complete};
}
} // namespace ax::ip4

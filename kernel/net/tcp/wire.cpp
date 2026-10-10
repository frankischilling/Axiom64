// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/wire.hpp"
#include "net/ipv4_wire.hpp"

namespace ax::tcp {
namespace {
uint16_t checksum(uint32_t source, uint32_t destination, const uint8_t* data, size_t length) {
    uint32_t sum = (source >> 16) + (source & 0xffff) + (destination >> 16) +
                   (destination & 0xffff) + 6 + length + uint16_t(~ip4::checksum(data, length));
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}
} // namespace

bool decode(uint32_t source, uint32_t destination, const void* packet, size_t length,
            Segment& output) {
    if (!packet || length < 20 || length > maximum_segment_size)
        return false;
    const auto* bytes = static_cast<const uint8_t*>(packet);
    size_t header = size_t(bytes[12] >> 4) * 4;
    if (header < 20 || header > length || checksum(source, destination, bytes, length))
        return false;
    Segment value{};
    value.source = ip4::get16(bytes);
    value.destination = ip4::get16(bytes + 2);
    value.sequence = ip4::get32(bytes + 4);
    value.acknowledgment = ip4::get32(bytes + 8);
    value.flags = bytes[13];
    value.window = ip4::get16(bytes + 14);
    value.urgent = ip4::get16(bytes + 18);
    for (size_t at = 20; at < header;) {
        uint8_t kind = bytes[at];
        if (!kind)
            break;
        if (kind == 1) {
            at++;
            continue;
        }
        if (header - at < 2)
            return false;
        size_t count = bytes[at + 1];
        if (count < 2 || count > header - at)
            return false;
        if (kind == 2) {
            if (count != 4)
                return false;
            if (value.flags & syn)
                value.maximum_segment = ip4::get16(bytes + at + 2);
        } else if (kind == 3) {
            if (count != 3)
                return false;
            if (value.flags & syn) {
                value.window_scale = bytes[at + 2] > 14 ? 14 : bytes[at + 2];
                value.has_window_scale = true;
            }
        } else if ((kind == 4 && count != 2) || (kind == 5 && (count < 10 || (count - 2) % 8)) ||
                   (kind == 8 && count != 10))
            return false;
        at += count;
    }
    value.payload = bytes + header;
    value.length = length - header;
    output = value;
    return true;
}

size_t encode(uint32_t source, uint32_t destination, const Segment& value, void* packet,
              size_t capacity) {
    size_t header = value.maximum_segment ? 24 : 20;
    if (!packet || value.has_window_scale || (value.maximum_segment && !(value.flags & syn)) ||
        (value.length && !value.payload) || value.length > maximum_segment_size - header ||
        header > capacity || value.length > capacity - header)
        return 0;
    auto* bytes = static_cast<uint8_t*>(packet);
    auto* destination_bytes = bytes + header;
    if (uintptr_t(destination_bytes) > uintptr_t(value.payload) &&
        uintptr_t(destination_bytes) - uintptr_t(value.payload) < value.length) {
        for (size_t at = value.length; at; at--)
            destination_bytes[at - 1] = value.payload[at - 1];
    } else
        for (size_t at = 0; at < value.length; at++)
            destination_bytes[at] = value.payload[at];
    for (size_t at = 0; at < header; at++)
        bytes[at] = 0;
    ip4::put16(bytes, value.source);
    ip4::put16(bytes + 2, value.destination);
    ip4::put32(bytes + 4, value.sequence);
    ip4::put32(bytes + 8, value.acknowledgment);
    bytes[12] = header / 4 << 4;
    bytes[13] = value.flags;
    ip4::put16(bytes + 14, value.window);
    ip4::put16(bytes + 18, value.urgent);
    if (value.maximum_segment) {
        bytes[20] = 2;
        bytes[21] = 4;
        ip4::put16(bytes + 22, value.maximum_segment);
    }
    size_t length = header + value.length;
    ip4::put16(bytes + 16, checksum(source, destination, bytes, length));
    return length;
}

uint32_t sequence_length(const Segment& value) {
    return value.length + bool(value.flags & syn) + bool(value.flags & fin);
}

bool before(uint32_t a, uint32_t b) {
    return int32_t(a - b) < 0;
}

bool acceptable(uint32_t sequence, uint32_t length, uint32_t next, uint32_t window) {
    if (!window)
        return !length && sequence == next;
    if (sequence - next < window)
        return true;
    return length && sequence + length - 1 - next < window;
}

Reset reset(uint32_t sequence, uint32_t next, uint32_t window) {
    if (sequence == next)
        return Reset::accept;
    return sequence - next < window ? Reset::challenge : Reset::ignore;
}
} // namespace ax::tcp

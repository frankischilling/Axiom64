// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/wire.hpp"

namespace ax::ip6 {
namespace {
uint16_t get16(const uint8_t* bytes) {
    return (uint16_t(bytes[0]) << 8) | bytes[1];
}

uint32_t get32(const uint8_t* bytes) {
    return (uint32_t(get16(bytes)) << 16) | get16(bytes + 2);
}

void put16(uint8_t* bytes, uint16_t value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}

void put32(uint8_t* bytes, uint32_t value) {
    put16(bytes, value >> 16);
    put16(bytes + 2, value);
}

Packet problem(Packet packet, uint8_t code, uint32_t pointer) {
    packet.input = Input::parameter_problem;
    packet.error_code = code;
    packet.error_pointer = pointer;
    return packet;
}

bool options(const uint8_t* bytes, size_t begin, size_t end, Packet& packet) {
    for (size_t at = begin; at < end;) {
        uint8_t type = bytes[at];
        if (!type) {
            at++;
            continue;
        }
        if (end - at < 2)
            return false;
        size_t length = size_t(bytes[at + 1]) + 2;
        if (length > end - at) {
            packet = problem(packet, 0, at + 1);
            return false;
        }
        // PadN and unrecognized skip-action options do not alter the payload.
        if (type == 1)
            for (size_t n = at + 2; n < at + length; n++)
                if (bytes[n])
                    return false;
        unsigned action = type >> 6;
        if (action) {
            if (action == 2 || (action == 3 && !packet.header.destination.multicast()))
                packet = problem(packet, 2, at);
            return false;
        }
        at += length;
    }
    return true;
}
} // namespace

bool Address::unspecified() const {
    for (auto byte : bytes)
        if (byte)
            return false;
    return true;
}

bool Address::multicast() const {
    return bytes[0] == 0xff;
}

bool Address::loopback() const {
    for (unsigned n = 0; n < 15; n++)
        if (bytes[n])
            return false;
    return bytes[15] == 1;
}

bool Address::link_local() const {
    return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
}

bool Address::mapped() const {
    for (unsigned n = 0; n < 10; n++)
        if (bytes[n])
            return false;
    return bytes[10] == 0xff && bytes[11] == 0xff;
}

bool Address::matches(const Address& prefix, unsigned bits) const {
    if (bits > 128)
        return false;
    unsigned full = bits / 8, partial = bits % 8;
    for (unsigned n = 0; n < full; n++)
        if (bytes[n] != prefix.bytes[n])
            return false;
    return !partial || !((bytes[full] ^ prefix.bytes[full]) & (0xff << (8 - partial)));
}

Packet decode(const uint8_t* bytes, size_t length) {
    Packet packet;
    if (!bytes || length < header_size || bytes[0] >> 4 != 6)
        return packet;
    packet.header.payload_length = get16(bytes + 4);
    packet.size = header_size + packet.header.payload_length;
    if (packet.size > length)
        return packet;
    packet.header.flow_label = get32(bytes) & 0xfffff;
    packet.header.traffic_class = (get32(bytes) >> 20) & 0xff;
    packet.header.next_header = bytes[6];
    packet.header.hop_limit = bytes[7];
    for (unsigned n = 0; n < 16; n++) {
        packet.header.source.bytes[n] = bytes[8 + n];
        packet.header.destination.bytes[n] = bytes[24 + n];
    }
    uint8_t next = bytes[6];
    size_t at = header_size;
    // Each extension advances at least eight bytes inside the 16-bit payload.
    // AH and ESP remain opaque; decoding cannot authorize their inner payload.
    while (next == 0 || next == 43 || next == 44 || next == 60) {
        if (next == 0 && at != header_size)
            return problem(packet, 1, packet.next_header_offset);
        if (packet.size - at < 8)
            return packet;
        size_t extension = next == 44 ? 8 : (size_t(bytes[at + 1]) + 1) * 8;
        if (extension > packet.size - at)
            return problem(packet, 0, at + 1);
        if ((next == 0 || next == 60) && !options(bytes, at + 2, at + extension, packet))
            return packet;
        // RFC 8200 and RFC 5095 treat unsupported routing types, including RH0,
        // as ignorable only when no segments remain. This host never forwards.
        if (next == 43 && bytes[at + 3])
            return problem(packet, 0, at + 2);
        if (next == 44) {
            if (packet.fragmented)
                return packet;
            packet.fragmented = true;
            uint16_t field = get16(bytes + at + 2);
            packet.fragment = {get32(bytes + at + 4), uint16_t(field & 0xfff8), bool(field & 1)};
            size_t fragment_length = packet.size - at - 8;
            if (packet.fragment.more && fragment_length % 8)
                return problem(packet, 0, 4);
            // Only the offset-zero fragment's preceding headers survive.
            // Reassembly must add that saved prefix, not this fragment's prefix.
            if (packet.fragment.offset + fragment_length > 65535)
                return problem(packet, 0, at + 2);
            // A real fragment must reach reassembly before any inner header is
            // interpreted. Atomic fragments bypass all shared fragment state.
            if (packet.fragment.offset || packet.fragment.more) {
                packet.input = Input::fragment;
                packet.protocol = bytes[at];
                packet.next_header_offset = at;
                packet.payload = bytes + at + 8;
                packet.length = fragment_length;
                return packet;
            }
        }
        next = bytes[at];
        packet.next_header_offset = at;
        at += extension;
    }
    packet.protocol = next;
    if (next == 59) {
        packet.input = Input::no_next_header;
        return packet;
    }
    packet.input = Input::payload;
    packet.payload = bytes + at;
    packet.length = packet.size - at;
    return packet;
}

bool encode(uint8_t* bytes, size_t capacity, const Header& header) {
    if (!bytes || capacity < header_size || header.flow_label > 0xfffff)
        return false;
    put32(bytes, 0x60000000 | (uint32_t(header.traffic_class) << 20) | header.flow_label);
    put16(bytes + 4, header.payload_length);
    bytes[6] = header.next_header;
    bytes[7] = header.hop_limit;
    for (unsigned n = 0; n < 16; n++) {
        bytes[8 + n] = header.source.bytes[n];
        bytes[24 + n] = header.destination.bytes[n];
    }
    return true;
}

uint16_t checksum(const Address& source, const Address& destination, uint8_t protocol,
                  const uint8_t* bytes, uint32_t length) {
    uint64_t sum = (length >> 16) + (length & 0xffff) + protocol;
    for (unsigned n = 0; n < 16; n += 2)
        sum += get16(source.bytes + n) + get16(destination.bytes + n);
    while (length >= 2) {
        sum += get16(bytes);
        bytes += 2;
        length -= 2;
    }
    if (length)
        sum += uint16_t(*bytes) << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return uint16_t(~sum);
}
} // namespace ax::ip6

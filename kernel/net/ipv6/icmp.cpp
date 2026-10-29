// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/icmp.hpp"
#include "core/base.hpp"

namespace ax::ip6 {
bool error_quote(const uint8_t* bytes, size_t length, ErrorQuote& result) {
    if (length < 8 + header_size + 8 || bytes[0] < 1 || bytes[0] > 4 || (bytes[8] >> 4) != 6)
        return false;
    const auto quote = bytes + 8;
    size_t quoted = length - 8, declared = header_size + (size_t(quote[4]) << 8 | quote[5]);
    quoted = min(quoted, declared);
    const uint8_t* final = quote + 24;
    bool routing_seen = false;
    uint8_t protocol = quote[6];
    size_t at = header_size;
    for (unsigned depth = 0;
         protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60 || protocol == 51;
         depth++) {
        if (depth == 16 || at > quoted || quoted - at < 8)
            return false;
        size_t size = protocol == 44   ? 8
                      : protocol == 51 ? (size_t(quote[at + 1]) + 2) * 4
                                       : (size_t(quote[at + 1]) + 1) * 8;
        if (size > quoted - at || (protocol == 44 && (quote[at + 2] || (quote[at + 3] & 0xf8))))
            return false;
        if (protocol == 43) {
            if (!routing_seen && valid_segment_routing(quote + at, size, true))
                final = quote + at + 8;
            routing_seen = true;
        }
        protocol = quote[at];
        at += size;
    }
    if ((protocol != 6 && protocol != 17 && protocol != 58) || at > quoted || quoted - at < 8 ||
        (protocol == 6 && declared - at < 20))
        return false;
    ErrorQuote value;
    memcpy(value.source.bytes, quote + 8, 16);
    memcpy(value.destination.bytes, quote + 24, 16);
    memcpy(value.transport_destination.bytes, protocol == 6 || protocol == 17 ? final : quote + 24,
           16);
    if (value.source.unspecified() || value.source.multicast() || value.source.mapped() ||
        value.destination.unspecified() || value.destination.multicast() ||
        value.destination.mapped() || value.transport_destination.unspecified() ||
        value.transport_destination.multicast() || value.transport_destination.mapped())
        return false;
    value.transport = quote + at;
    value.length = quoted - at;
    value.protocol = protocol;
    value.type = bytes[0];
    value.code = bytes[1];
    value.information =
        uint32_t(bytes[4]) << 24 | uint32_t(bytes[5]) << 16 | uint32_t(bytes[6]) << 8 | bytes[7];
    if (value.type == 1) {
        constexpr int errors[] = {101, 13, 113, 113, 111, 13, 13};
        value.error = value.code < sizeof(errors) / sizeof(*errors) ? errors[value.code] : 71;
        value.hard = value.code != 0 && value.code != 2 && value.code != 3;
    } else if (value.type == 2)
        value.error = 90;
    else if (value.type == 3)
        value.error = 113;
    else {
        value.error = 71;
        value.hard = true;
    }
    result = value;
    return true;
}
} // namespace ax::ip6

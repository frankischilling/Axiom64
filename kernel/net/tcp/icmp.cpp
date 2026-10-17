// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/icmp.hpp"
#include "net/ipv4_wire.hpp"

namespace ax::tcp {
bool decode_icmp_error(const uint8_t* bytes, size_t length, IcmpError& result) {
    if (!bytes || length < 36 || ip4::checksum(bytes, length))
        return false;
    int error = 0;
    bool abort_request = false;
    bool too_big = bytes[0] == 3 && bytes[1] == 4;
    if (bytes[0] == 3 && bytes[1] < 16) {
        // Fragmentation-needed carries a path limit rather than a fatal TCP error.
        constexpr int unreachable[] = {101, 113, 92,  111, 0,   95,  101, 112,
                                       64,  101, 113, 101, 113, 113, 113, 113};
        error = unreachable[bytes[1]];
        abort_request = bytes[1] < 2;
    } else if (bytes[0] == 11 && bytes[1] == 0) {
        error = 113;
        abort_request = true;
    } else if (bytes[0] == 12 && bytes[1] < 3) {
        error = 71;
        abort_request = true;
    }
    if (!error && !too_big)
        return false;
    const auto quote = bytes + 8;
    size_t header = size_t(quote[0] & 15) * 4;
    if ((quote[0] >> 4) != 4 || header < 20 || length - 8 < header + 8 ||
        ip4::get16(quote + 2) < header + 20 || ip4::checksum(quote, header) ||
        (ip4::get16(quote + 6) & ~uint16_t(0x4000)) || quote[9] != 6 ||
        !ip4::unicast(ip4::get32(quote + 12)) || !ip4::unicast(ip4::get32(quote + 16)))
        return false;
    result = {ip4::get32(quote + 12),
              ip4::get32(quote + 16),
              ip4::get32(quote + header + 4),
              ip4::get16(quote + header),
              ip4::get16(quote + header + 2),
              error,
              abort_request};
    result.too_big = too_big;
    if (too_big) {
        result.next_hop_mtu = ip4::get16(bytes + 6);
        result.quoted_length = ip4::get16(quote + 2);
    }
    return true;
}

uint16_t quoted_path_mtu(const IcmpError& quote) {
    if (!quote.too_big)
        return 0;
    if (quote.next_hop_mtu)
        return quote.next_hop_mtu >= 68 && quote.next_hop_mtu < quote.quoted_length
                   ? quote.next_hop_mtu
                   : 0;
    // RFC 1191 plateaus make old-router notifications converge without increasing a limit.
    constexpr uint16_t plateaus[] = {65535, 32000, 17914, 8166, 4352, 2002,
                                     1492,  1006,  508,   296,  68};
    for (auto mtu : plateaus)
        if (mtu < quote.quoted_length)
            return mtu;
    return 0;
}
} // namespace ax::tcp

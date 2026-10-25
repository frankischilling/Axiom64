// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6/wire.hpp"

namespace ax::tcp {
// IPv4 tuples use their mapped representation, so both socket domains name one
// transport endpoint. Native IPv6 addresses retain all sixteen network bytes.
struct Address {
    ip6::Address bytes;

    static Address ipv4(uint32_t value) {
        Address address;
        address.bytes.bytes[10] = address.bytes.bytes[11] = 0xff;
        for (unsigned n = 0; n < 4; n++)
            address.bytes.bytes[12 + n] = uint8_t(value >> (24 - 8 * n));
        return address;
    }

    static Address ipv6(const ip6::Address& value) {
        return {value};
    }

    bool is_ipv4() const {
        return bytes.mapped();
    }

    uint32_t ipv4() const {
        uint32_t value = 0;
        for (unsigned n = 12; n < 16; n++)
            value = (value << 8) | bytes.bytes[n];
        return value;
    }

    bool unspecified() const {
        return is_ipv4() ? !ipv4() : bytes.unspecified();
    }

    bool operator==(const Address&) const = default;
};

struct Binding {
    Address local;
    unsigned index = 0;
    bool dual = false;

    bool accepts(const Address& address, unsigned incoming) const {
        return (!index || index == incoming) &&
               (local == address ||
                (local.unspecified() && (dual || local.is_ipv4() == address.is_ipv4())));
    }

    bool overlaps(const Binding& other) const {
        if (index && other.index && index != other.index)
            return false;
        if (local.is_ipv4() != other.local.is_ipv4())
            return (dual && local.unspecified()) || (other.dual && other.local.unspecified());
        return local.unspecified() || other.local.unspecified() || local == other.local;
    }
};
} // namespace ax::tcp

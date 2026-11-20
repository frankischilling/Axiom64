// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/tcp/address.hpp
 * @brief   TCP endpoint addresses.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares address helpers used to compare TCP endpoints and bind them to
 * network paths.
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

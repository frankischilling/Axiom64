// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/net/ipv6_disabled.cpp
 * @brief   Disabled IPv6 interface tests.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Checks behavior while IPv6 is disabled on an interface.
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
// An empty IPv6 namespace for the isolated IPv4 netlink codec fixtures.
#include "net/netlink.hpp"
#include "net/ipv6/configuration.hpp"

namespace ax {
int netlink_link_change(const void*, const NetlinkHeader&) {
    return -95;
}

namespace ip6 {
int configuration_read(unsigned, ConfigurationKey key, int32_t& value) {
    if (key != ConfigurationKey::generation_mode)
        return -97;
    value = 0;
    return 0;
}
} // namespace ip6

const Ipv6Address* ipv6_address(unsigned) {
    return nullptr;
}

Ipv6AddressCacheInfo ipv6_address_cache(const Ipv6Address&) {
    return {0, 0, 0, 0};
}

int netlink_ipv6_address_change(const void*, const NetlinkHeader&) {
    return -97;
}

int netlink_ipv6_route(const void* data, const NetlinkHeader& request, uint32_t port, void* output,
                       size_t capacity, size_t& size, bool) {
    if (request.type != 26 || static_cast<const uint8_t*>(data)[16])
        return -97;
    if (capacity < 20)
        return -90;
    NetlinkHeader done{20, 3, 2, request.sequence, port};
    memcpy(output, &done, sizeof(done));
    memset(static_cast<uint8_t*>(output) + 16, 0, 4);
    size = 20;
    return 0;
}
} // namespace ax

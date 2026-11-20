// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv6/destination.hpp
 * @brief   IPv6 destination selection interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the destination policy used to select routes, interfaces, and source
 * addresses.
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
#include "net/ipv6.hpp"
#include "net/ipv6/path_mtu.hpp"

namespace ax {
// One description owns the selected path and its held metric. Clear it before
// reusing the description; copying the fields does not acquire another owner.
struct Ipv6Destination {
    Ipv6Path path;
    ip6::Address address;
    ip6::PathMtuReference metric;
    const NetInfo* adapter = nullptr;
    bool valid = false;
};

void ipv6_destination_clear(Ipv6Destination&);
void ipv6_destination_store(Ipv6Destination&, const Ipv6Path&, const ip6::Address&);
int ipv6_destination_mtu(const Ipv6Destination&, uint32_t&);
uint8_t ipv6_destination_hops(const Ipv6Destination&);
} // namespace ax

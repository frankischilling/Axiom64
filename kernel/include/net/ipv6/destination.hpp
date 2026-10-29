// SPDX-License-Identifier: GPL-3.0-or-later
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

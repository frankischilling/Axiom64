// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6.hpp"

namespace ax {
struct Ipv6Address;
}

namespace ax::ip6 {
// Receive borrows the validated datagram only for the duration of this call.
void router_receive(unsigned index, const Packet&);

// Retire learned prefix ownership only after the actual address leaves the inventory.
void router_address_removed(const Ipv6Address&, uint64_t owner);

// Update only the cached owner participating in this successful handoff.
void router_address_regenerated(const Ipv6Address&, uint64_t owner, const Ipv6Address&,
                                uint64_t replacement_owner, unsigned counter);

void router_poll();

void router_reset();

void router_link_reset(unsigned index);

uint32_t link_mtu(unsigned index);

uint8_t link_hop_limit(unsigned index);

uint64_t link_retransmit(unsigned index);

uint64_t link_reachable(unsigned index);
} // namespace ax::ip6

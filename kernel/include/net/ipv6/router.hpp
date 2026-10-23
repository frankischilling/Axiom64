// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6.hpp"

namespace ax::ip6 {
// Receive borrows the validated datagram only for the duration of this call.
void router_receive(unsigned index, const Packet&);

void router_poll();

void router_reset();

void router_link_reset(unsigned index);

uint32_t link_mtu(unsigned index);

uint8_t link_hop_limit(unsigned index);

uint64_t link_retransmit(unsigned index);

uint64_t link_reachable(unsigned index);
} // namespace ax::ip6

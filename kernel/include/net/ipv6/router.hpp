// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv6/router.hpp
 * @brief   IPv6 router advertisement interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines router advertisement state and declares router and prefix processing
 * operations.
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

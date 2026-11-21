// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/net/ipv6_host_fixture.hpp
 * @brief   Shared IPv6 host test fixture.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the simulated interfaces and test cases used by the IPv6 host runner.
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

#include "net/ipv6/host.hpp"
#include <unordered_set>
#include <vector>

namespace ipv6_fixture {
extern std::unordered_set<void*> allocations;
extern std::vector<std::vector<uint8_t>> emitted[2];
extern ax::NetAdapter adapters[2];
extern unsigned blocked, send_budget, fail_allocations;
extern unsigned shutdown_after_polls, remove_after_polls, shrink_after_polls;
extern unsigned callback_index, inject_after_polls;
extern std::vector<uint8_t> injected_frame;
extern bool entropy_available;

ax::ip6::Address address(unsigned lane, unsigned host, bool link = false);
int change(unsigned index, const ax::ip6::Address& value, bool nodad = true, bool remove = false,
           uint8_t prefix = 64);
void reset();
std::vector<uint8_t> incoming(unsigned lane, const ax::ip6::Address& source,
                              const ax::ip6::Address& destination, std::vector<uint8_t> data,
                              unsigned hop = 255, uint8_t protocol = 58);
std::vector<uint8_t> solicitation(unsigned lane, const ax::ip6::Address& target, bool dad = false,
                                  unsigned hop = 255);
std::vector<uint8_t> advertisement(unsigned lane, const ax::ip6::Address& target,
                                   const ax::ip6::Address& destination);
void deliver(unsigned lane, const std::vector<uint8_t>& frame);
ax::ip6::Packet last(unsigned lane, uint8_t type);
int route(const ax::Ipv6Route& value, bool remove, bool privileged = true, unsigned flags = 0x605);

void cached_routing_output();
void copied_error_queues();
void copied_extension_output();
void copied_routing_output();
void copied_sticky_output(unsigned mode);
void fragmented_delivery();
void path_mtu_errors();
void per_message_controls();
void raw_header_bounds();
void receive_extension_policy();
void routed_error_destinations(unsigned mode);
void socket_ownership();
void source_fragmentation();
void sticky_extension_controls();
void automatic_link_configuration();
void configuration_files();
void cross_interface_source_output();
void finite_address_dad();
void finite_address_lifetimes();
void finite_prefix_lifetimes();
void fresh_link_dad_cycles();
void legacy_route_inventory();
void local_route_visibility();
void loopback_source_mtu();
void loopback_source_output();
void manual_source_policy();
void prefix_lifetimes();
void prefix_route_order();
void queued_automatic_source_removal();
void retained_address_expiry();
void retired_neighbor_source();
void reviewed_source_edges();
void source_lifetime_preferences();
} // namespace ipv6_fixture

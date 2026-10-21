// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv6.hpp"
#include "core/time.hpp"
#include "net/ipv6/path_mtu.hpp"

namespace ax::ip6 {
extern PathMtuCache path_mtu_cache;

inline PathKey path_key(const Ipv6Path& path, const Address& destination) {
    return {path.source, destination, path.next_hop, path.index, path.route_owner};
}

Address solicited_node(const Address&);

Address all_nodes();

void multicast_mac(const Address&, uint8_t*);

bool usable(unsigned index);

int queue_control(unsigned index, const Address& source, const Address& destination, const void*,
                  size_t);

void output_poll();

void output_shutdown();

void address_poll();

void address_duplicate(unsigned index, const Address&);

void address_reset();

int prefix_add(const Ipv6Address&);

void prefix_remove(const Ipv6Address&);

void route_reset();

int dad_probe(const Ipv6Address&);

void neighbor_reset();

void neighbor_poll();

// Only a pending solicitation can install a new neighbor advertisement.
void neighbor_advertisement(unsigned index, const Address&, const uint8_t* mac, bool solicited,
                            bool override_mac);

void neighbor_solicitation(unsigned index, const Address&, const uint8_t* mac);

bool neighbor_resolve(unsigned index, const Address& source, const Address& target, uint8_t* mac);

int neighbor_probe(unsigned index, const Address& source, const Address& target,
                   const uint8_t* unicast_mac = nullptr);
} // namespace ax::ip6

// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ethernet.hpp"
#include "net/ipv6/wire.hpp"

namespace ax {
struct Inet6Socket;
constexpr unsigned ipv6_address_capacity = 16, ipv6_route_capacity = 16;
constexpr unsigned ipv6_loopback = max_net_devices + 1;

struct Ipv6Address {
    ip6::Address address;
    unsigned index = 0;
    uint16_t flags = 0x80;
    uint8_t prefix = 128;
};

struct Ipv6Route {
    ip6::Address destination, gateway;
    unsigned index = 0, metric = 1024;
    uint8_t prefix = 0, protocol = 3;
    uint64_t owner = 0;
};

struct Ipv6Path {
    ip6::Address source, next_hop;
    unsigned index = 0;
    uint32_t mtu = 0;
    uint64_t route_owner = 0;
};

// Serialized borrowers retain an entry only until the next address mutation.
const Ipv6Address* ipv6_address(unsigned position);

int ipv6_address_add(const Ipv6Address&);

int ipv6_address_remove(unsigned index, const ip6::Address&);

bool ipv6_owned(unsigned index, const ip6::Address&, bool tentative = false);

int ipv6_route_control(const Ipv6Route&, bool remove, bool exclusive);

size_t ipv6_routes(Ipv6Route*, size_t capacity);

int ipv6_path(const ip6::Address& source, const ip6::Address& destination, unsigned bound_index,
              Ipv6Path&, bool interface_mtu = false);

void ipv6_mtu_changed(unsigned index, uint32_t previous);

// Success owns a copy until device acceptance or bounded resolution failure.
int ipv6_send(const ip6::Address& source, const ip6::Address& destination, unsigned bound_index,
              uint8_t protocol, uint8_t hop_limit, const void*, size_t,
              Inet6Socket* owner = nullptr, bool fragmentable = true, uint32_t socket_mtu = 0,
              bool interface_mtu = false);

bool ipv6_output_ready();

// Queued bytes outlive a closed socket, without callbacks to a reused slot.
void ipv6_detach_owner(Inet6Socket*);

void ipv6_receive(const NetInfo&, const void*, size_t);

void ipv6_poll();

void ipv6_shutdown();
} // namespace ax

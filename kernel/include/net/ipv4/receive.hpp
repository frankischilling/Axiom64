// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"
#include "net/ipv4/options.hpp"

namespace ax {
// Input snapshots use host-order IPv4 addresses. No address or route inventory
// entry remains borrowed after the datagram enters a socket queue.
struct Ipv4ReceiveMetadata {
    unsigned index;
    uint32_t source, destination, specific_destination;
    uint8_t protocol, ttl, tos;
    ip4::ReceivedOptions options{};
};

struct Ipv4ReceiveOptions {
    bool packet_info = false, ttl = false, tos = false;
    bool options = false, return_options = false;
};
} // namespace ax

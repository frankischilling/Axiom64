// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4.hpp"
#include "net/ipv4/receive.hpp"

namespace ax {
struct InetSocket;

struct UdpOutput {
    Ipv4Source source;
    uint32_t destination;
    unsigned index;
    uint16_t source_port, destination_port;
    uint8_t ttl;
    bool broadcast;
    bool cache_destination = true;
    int traffic_class = -1;
    const Ipv4SendRoute* selected = nullptr;
};

enum class UdpInput { dropped, unbound, delivered };

UdpInput udp_receive(const Ipv4ReceiveMetadata&, bool broadcast, const void*, size_t);

int udp_send(InetSocket* owner, const UdpOutput&, const void*, size_t);
} // namespace ax

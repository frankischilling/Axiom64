// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct InetSocket;

struct UdpOutput {
    uint32_t source, destination;
    unsigned index;
    uint16_t source_port, destination_port;
    uint8_t ttl;
    bool broadcast;
};

enum class UdpInput { dropped, unbound, delivered };

UdpInput udp_receive(unsigned index, uint32_t source, uint32_t destination, bool broadcast,
                     const void*, size_t);

int udp_send(InetSocket* owner, const UdpOutput&, const void*, size_t);
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/udp.hpp
 * @brief   UDP socket interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares datagram endpoint lifecycle, send and receive, readiness, and error
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
    const ip4::Options* options = nullptr;
};

enum class UdpInput { dropped, unbound, delivered };

UdpInput udp_receive(const Ipv4ReceiveMetadata&, bool broadcast, const void*, size_t);

int udp_send(InetSocket* owner, const UdpOutput&, const void*, size_t);
} // namespace ax

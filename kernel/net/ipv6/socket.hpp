// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/ipv6/socket.hpp
 * @brief   IPv6 socket internals.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines internal IPv6 socket state shared by the protocol, option, and
 * ancillary handlers.
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
#include "net/inet6.hpp"
#include "net/ipv6.hpp"
#include "net/ipv6/destination.hpp"
#include "net/ipv6/errors.hpp"
#include "net/ipv6/path_mtu.hpp"
#include "net/udp/cork.hpp"

namespace ax {
constexpr unsigned inet6_socket_count = 256, inet6_queue_count = 32;
constexpr uint32_t inet6_queue_bytes = 65536;
constexpr uint8_t inet6_default_multicast_hops = 1;
static_assert(inet6_socket_count <= ip6::path_mtu_reference_capacity);
using Inet6UdpCork = UdpCork<Inet6Address, Inet6SendControl>;

struct Inet6Socket {
    bool used = false, bound = false, connected = false, reuse = false, port_locked = false;
    bool v6only = false, dont_fragment = false, receive_errors = false;
    bool receive_packet_info = false, receive_hops = false, receive_traffic_class = false;
    bool receive_legacy_hops = false;
    bool receive_hop_options = false, receive_routing = false, receive_destination_options = false;
    uint8_t type = 3, protocol = 58, pmtu_mode = 1, traffic_class = 0;
    int16_t hops = -1;
    uint8_t multicast_hops = inet6_default_multicast_hops;
    uint32_t socket_mtu = 0;
    unsigned index = 0, head = 0, count = 0, shutdown = 0;
    uint16_t local_port = 0, peer_port = 0;
    ip6::Address local, peer;
    Ipv6Destination destination;
    // Each stored header owns its allocation; aliases share this description.
    ip6::OutputExtensions extensions;
    uint32_t filter[8]{};
    uint32_t receive_limit = inet6_queue_bytes, send_limit = 212992;
    size_t bytes = 0, transmitted = 0;
    uint64_t order = 0;
    int error = 0;
    Inet6Frame* queue[inet6_queue_count]{};
    Inet6Error* errors[inet6_queue_count]{};
    unsigned error_head = 0, error_count = 0;
    size_t error_bytes = 0;
    Inet6UdpCork* cork = nullptr;
    bool udp_cork = false;
};

extern Inet6Socket inet6_sockets[inet6_socket_count];
Inet6Socket* inet6_allocate(unsigned type);
int inet6_bind_port(Inet6Socket*, const ip6::Address&, uint16_t port);
ip6::Address inet6_destination_output(Inet6Socket*, const Ipv6Path&, const ip6::Address& first,
                                      const ip6::Address& requested);
void inet6_icmp_error(unsigned index, const ip6::Packet&, const uint8_t*, size_t);
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/inet.hpp"
#include "net/ipv4.hpp"
#include "net/ipv6/destination.hpp"
#include "net/tcp/address.hpp"

namespace ax::tcp {
class Connection;
}

namespace ax {
constexpr unsigned inet_socket_count = 256, inet_queue_count = 32;
constexpr uint32_t inet_queue_bytes = 65536;

struct InetSocket {
    bool used = false, broadcast = false, bound = false, port_locked = false, reuse = false;
    unsigned index = 0, head = 0, count = 0;
    uint32_t local = 0, peer = 0, receive_limit = inet_queue_bytes, send_limit = inet_queue_bytes;
    uint32_t filter = 0;
    size_t bytes = 0, transmitted = 0;
    unsigned mtu_policy = 1;
    Ipv4Destination destination;
    int error = 0;
    uint8_t ttl = 64, tos = 0;
    uint8_t type = 3, protocol = 1;
    uint16_t peer_port = 0, local_port = 0, reported_port = 0;
    unsigned shutdown = 0;
    uint64_t order = 0;
    InetFrame* queue[inet_queue_count]{};

    // Stream descriptions share one engine and port table across Internet domains.
    bool ipv6 = false, wire6 = false, v6only = false, bind_completed = false;
    ip6::Address local6, peer6;
    Ipv6Destination destination6;
    int16_t hops = -1;
    uint8_t traffic_class = 0;

    tcp::Binding binding(uint32_t local4) const {
        return {wire6 ? tcp::Address::ipv6(local6) : tcp::Address::ipv4(local4), index,
                ipv6 && wire6 && !v6only && local6.unspecified()};
    }

    tcp::Address stream_local() const {
        return wire6 ? tcp::Address::ipv6(local6) : tcp::Address::ipv4(local);
    }

    tcp::Address stream_peer() const {
        return wire6 ? tcp::Address::ipv6(peer6) : tcp::Address::ipv4(peer);
    }

    tcp::Connection* stream = nullptr;
    InetSocket* listener = nullptr;
    InetSocket* accepted[inet_queue_count]{};
    unsigned accept_head = 0, accept_count = 0, children = 0, backlog = 0;
    bool listening = false, detached = false, error_seen = false, nodelay = false;
    bool connect_pending = false;
    uint32_t user_timeout = 0;
    uint16_t user_mss = 0, mss_cache = 536;
    bool accept_queued = false;
    uint16_t time_wait_slot = UINT16_MAX;
    uint64_t generation = 1;
    uint32_t restart_sequence = 0;
    bool restart_valid = false;
};

extern InetSocket inet_sockets[inet_socket_count];
InetSocket* inet_allocate(unsigned type);
void inet_dispose(InetSocket*);
bool inet_port_conflict(InetSocket*, uint32_t local, uint16_t port);
int inet_bind_port(InetSocket*, uint32_t local, uint16_t port);
} // namespace ax

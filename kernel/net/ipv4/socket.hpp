// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/inet.hpp"
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "net/ipv4/multicast.hpp"
#include "net/ipv4/options.hpp"
#include "net/ipv6/destination.hpp"
#include "net/tcp/address.hpp"

namespace ax::tcp {
class Connection;
}

namespace ax {
constexpr unsigned inet_socket_count = 256, inet_queue_count = 32;
constexpr uint32_t inet_queue_bytes = 65536;
constexpr int inet_protocol_limit = 263; // Linux IPPROTO_MAX includes MPTCP, 262.

struct InetSocket {
    bool used = false, broadcast = false, bound = false, port_locked = false, reuse = false;
    unsigned index = 0, head = 0, count = 0;
    uint32_t local = 0, peer = 0, receive_limit = inet_queue_bytes, send_limit = inet_queue_bytes;
    uint32_t filter = 0;
    size_t bytes = 0, transmitted = 0;
    unsigned mtu_policy = 1;
    Ipv4Destination destination;
    ip4::MulticastMembership multicast;
    int error = 0;
    uint8_t ttl = 64, tos = 0;
    Ipv4ReceiveOptions receive_options;
    ip4::Options options;
    ip4::Options input_options;
    bool input_options_valid = true;
    bool header_included = false;
    uint8_t type = 3;
    uint16_t protocol = 1;
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

inline InetSendControl inet_send_defaults(const InetSocket* socket, const InetAddress& address,
                                          bool named) {
    uint32_t destination = __builtin_bswap32(address.address);
    bool multicast = ip4::multicast(destination);
    InetSendControl result{Ipv4Source{ip4::multicast(socket->local) ? 0 : socket->local},
                           socket->index, multicast ? socket->multicast.ttl : socket->ttl,
                           socket->tos,
                           socket->type == 3 || (!named && destination == socket->peer)};
    result.options = socket->options;
    result.header_included = socket->type == 3 && socket->header_included;
    if (multicast) {
        if (!result.index)
            result.index = socket->multicast.output_index;
        if (!result.source.selected && socket->multicast.output_address)
            result.source = socket->multicast.output_address;
    }
    return result;
}

InetSocket* inet_allocate(unsigned type);
bool inet_option_unicast(uint32_t address, void*);
void inet_dispose(InetSocket*);
bool inet_port_conflict(InetSocket*, uint32_t local, uint16_t port);
int inet_bind_port(InetSocket*, uint32_t local, uint16_t port);
} // namespace ax

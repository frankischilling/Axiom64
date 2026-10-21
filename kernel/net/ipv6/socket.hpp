// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/inet6.hpp"
#include "net/ipv6.hpp"
#include "net/ipv6/errors.hpp"
#include "net/ipv6/path_mtu.hpp"

namespace ax {
constexpr unsigned inet6_socket_count = 256, inet6_queue_count = 32;
constexpr uint32_t inet6_queue_bytes = 65536;
static_assert(inet6_socket_count <= ip6::path_mtu_reference_capacity);

struct Inet6Destination {
    Ipv6Path path;
    ip6::PathMtuReference metric;
    const NetInfo* adapter = nullptr;
    bool valid = false;
};

struct Inet6Socket {
    bool used = false, bound = false, connected = false, reuse = false, port_locked = false;
    bool v6only = false, dont_fragment = false, receive_errors = false;
    uint8_t type = 3, protocol = 58, hops = 64, pmtu_mode = 1;
    uint32_t socket_mtu = 0;
    unsigned index = 0, head = 0, count = 0, shutdown = 0;
    uint16_t local_port = 0, peer_port = 0;
    ip6::Address local, peer;
    Inet6Destination destination;
    uint32_t filter[8]{};
    uint32_t receive_limit = inet6_queue_bytes, send_limit = 212992;
    size_t bytes = 0, transmitted = 0;
    uint64_t order = 0;
    int error = 0;
    Inet6Frame* queue[inet6_queue_count]{};
    Inet6Error* errors[inet6_queue_count]{};
    unsigned error_head = 0, error_count = 0;
    size_t error_bytes = 0;
};

extern Inet6Socket inet6_sockets[inet6_socket_count];
Inet6Socket* inet6_allocate(unsigned type);
int inet6_bind_port(Inet6Socket*, const ip6::Address&, uint16_t port);
void inet6_destination_clear(Inet6Socket*);
void inet6_destination_store(Inet6Socket*, const Ipv6Path&, const ip6::Address&);
int inet6_destination_mtu(Inet6Socket*, uint32_t&);
void inet6_icmp_error(unsigned index, const ip6::Address& offender, const uint8_t*, size_t);
} // namespace ax

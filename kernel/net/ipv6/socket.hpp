// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/inet6.hpp"
#include "net/ipv6.hpp"

namespace ax {
constexpr unsigned inet6_socket_count = 256, inet6_queue_count = 32;
constexpr uint32_t inet6_queue_bytes = 65536;

struct Inet6Socket {
    bool used = false, bound = false, connected = false, reuse = false, port_locked = false;
    bool v6only = false;
    uint8_t type = 3, protocol = 58, hops = 64;
    unsigned index = 0, head = 0, count = 0, shutdown = 0;
    uint16_t local_port = 0, peer_port = 0;
    ip6::Address local, peer;
    uint32_t filter[8]{};
    uint32_t receive_limit = inet6_queue_bytes, send_limit = inet6_queue_bytes;
    size_t bytes = 0, transmitted = 0;
    uint64_t order = 0;
    int error = 0;
    Inet6Frame* queue[inet6_queue_count]{};
};

extern Inet6Socket inet6_sockets[inet6_socket_count];
Inet6Socket* inet6_allocate(unsigned type);
int inet6_bind_port(Inet6Socket*, const ip6::Address&, uint16_t port);
} // namespace ax

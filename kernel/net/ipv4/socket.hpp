// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/inet.hpp"

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
    int error = 0;
    uint8_t ttl = 64;
    uint8_t type = 3, protocol = 1;
    uint16_t peer_port = 0, local_port = 0;
    unsigned shutdown = 0;
    uint64_t order = 0;
    InetFrame* queue[inet_queue_count]{};

    tcp::Connection* stream = nullptr;
    InetSocket* listener = nullptr;
    InetSocket* accepted[inet_queue_count]{};
    unsigned accept_head = 0, accept_count = 0, children = 0, backlog = 0;
    bool listening = false, detached = false, error_seen = false, nodelay = false;
    uint32_t user_timeout = 0;
    uint16_t maximum_segment = 1460;
    unsigned stream_index = 0;
    bool accept_queued = false;
};

extern InetSocket inet_sockets[inet_socket_count];
InetSocket* inet_allocate(unsigned type);
void inet_dispose(InetSocket*);
int inet_bind_port(InetSocket*, uint32_t local, uint16_t port);
} // namespace ax

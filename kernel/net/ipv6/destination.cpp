// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket.hpp"
#include "net/ipv6/host.hpp"

namespace ax {
void inet6_destination_clear(Inet6Socket* socket) {
    ip6::path_mtu_cache.release(socket->destination.metric);
    socket->destination = {};
}

void inet6_destination_store(Inet6Socket* socket, const Ipv6Path& path,
                             const ip6::Address& destination) {
    inet6_destination_clear(socket);
    socket->destination.path = path;
    socket->destination.metric =
        ip6::path_mtu_cache.retain(ip6::path_key(path, destination), ticks);
    socket->destination.adapter = net_info(path.index);
    socket->destination.valid = true;
}

int inet6_destination_mtu(Inet6Socket* socket, uint32_t& value) {
    const auto& destination = socket->destination;
    if (!destination.valid)
        return -107;
    value = ip6::path_mtu_cache.metric(destination.metric);
    if (!value) {
        auto info = net_info(destination.path.index);
        value = info && info == destination.adapter ? info->mtu : destination.path.mtu;
    }
    return 0;
}
} // namespace ax

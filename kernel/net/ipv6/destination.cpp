// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket.hpp"
#include "../ipv4/socket.hpp"
#include "net/ipv6/host.hpp"
#include "net/ipv6/router.hpp"

namespace ax {
static_assert(inet6_socket_count + inet_socket_count <= ip6::path_mtu_reference_capacity);

void ipv6_destination_clear(Ipv6Destination& destination) {
    ip6::path_mtu_cache.release(destination.metric);
    destination = {};
}

void ipv6_destination_store(Ipv6Destination& destination, const Ipv6Path& path,
                            const ip6::Address& address) {
    ipv6_destination_clear(destination);
    destination.path = path;
    destination.address = address;
    destination.metric = ip6::path_mtu_cache.retain(ip6::path_key(path, address), ticks);
    destination.adapter = net_info(path.index);
    destination.valid = true;
}

int ipv6_destination_mtu(const Ipv6Destination& destination, uint32_t& value) {
    if (!destination.valid)
        return -107;
    value = ip6::path_mtu_cache.metric(destination.metric);
    if (!value) {
        auto info = net_info(destination.path.index);
        value =
            info && info == destination.adapter ? ip6::link_mtu(info->index) : destination.path.mtu;
    }
    return 0;
}

uint8_t ipv6_destination_hops(const Ipv6Destination& destination) {
    return destination.valid && destination.adapter == net_info(destination.path.index)
               ? ip6::link_hop_limit(destination.path.index)
               : 64;
}

static bool destination_reuses(Inet6Socket* socket, const Ipv6Path& path,
                               const ip6::Address& first) {
    const auto& destination = socket->destination;
    if (!destination.valid || destination.adapter != net_info(path.index) ||
        destination.path.route_prefix != path.route_prefix ||
        !(ip6::path_key(destination.path, destination.address) == ip6::path_key(path, first)))
        return false;
    // A held getter metric can survive expiry; output cannot reuse that exception.
    if (destination.metric)
        return ip6::path_mtu_cache.active(destination.metric, ip6::path_key(path, first), ticks);
    return path.route_prefix == 128 || first == socket->peer;
}

ip6::Address inet6_destination_output(Inet6Socket* socket, const Ipv6Path& path,
                                      const ip6::Address& first, const ip6::Address& requested) {
    // UDP can reuse a held route before restoring a Routing header's requested
    // final destination. Raw output always performs the full lookup.
    return socket->type == 2 && !(first == requested) && destination_reuses(socket, path, first)
               ? first
               : requested;
}
} // namespace ax

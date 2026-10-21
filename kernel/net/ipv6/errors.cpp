// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket.hpp"
#include "net/ipv6/host.hpp"
#include "net/ipv6/icmp.hpp"

namespace ax {
void inet6_icmp_error(unsigned index, const ip6::Address& offender, const uint8_t* bytes,
                      size_t length) {
    ip6::ErrorQuote quote;
    if (!ip6::error_quote(bytes, length, quote) ||
        !ipv6_owned(quote.source.link_local() ? index : 0, quote.source))
        return;
    auto learn = [&](unsigned bound, Inet6Socket* owner = nullptr) {
        Ipv6Path path;
        if (!ipv6_path(quote.source, quote.destination, bound, path, true)) {
            ip6::path_mtu_cache.learn(ip6::path_key(path, quote.destination), path.mtu,
                                      quote.information, ticks);
            if (owner && owner->connected)
                inet6_destination_store(owner, path, quote.destination);
        }
    };
    auto enqueue = [&](Inet6Socket& socket) {
        Inet6Error record;
        record.destination = {10, 0, 0, quote.destination,
                              quote.destination.link_local() ? index : 0};
        size_t skip = socket.type == 2 ? 8 : 0;
        if (skip)
            memcpy(&record.destination.port, quote.transport + 2, 2);
        record.offender = {10, 0, 0, offender, offender.link_local() ? index : 0};
        record.error = {uint32_t(quote.error), 3, quote.type, quote.code, 0, quote.information, 0};
        inet6_queue_error(&socket, record, quote.transport + skip, quote.length - skip);
    };
    // ICMPv6 also receives errors about its own protocol independently of raw
    // descriptions. A closed raw socket does not invalidate a route exception.
    if (quote.type == 2 && quote.protocol == 58)
        learn(index);
    Inet6Socket* udp = nullptr;
    unsigned best_score = 0;
    for (auto& socket : inet6_sockets) {
        if (!socket.used || socket.protocol != quote.protocol ||
            (socket.index && socket.index != index && index != ipv6_loopback) ||
            (!socket.local.unspecified() && !(socket.local == quote.source)) ||
            (socket.connected && !(socket.peer == quote.destination)))
            continue;
        if (socket.type == 2) {
            if (!socket.local_port ||
                socket.local_port != (uint16_t(quote.transport[0]) << 8 | quote.transport[1]) ||
                (socket.connected &&
                 socket.peer_port != (uint16_t(quote.transport[3]) << 8 | quote.transport[2])))
                continue;
            unsigned score = (!socket.local.unspecified() ? 4 : 0) + (socket.connected ? 8 : 0) +
                             (socket.index ? 4 : 0);
            if (!udp || score > best_score || (score == best_score && socket.order > udp->order)) {
                udp = &socket;
                best_score = score;
            }
        } else if (socket.connected || socket.receive_errors) {
            if (quote.type == 2)
                learn(socket.index, &socket);
            enqueue(socket);
            if (socket.receive_errors || (quote.type == 2 ? socket.pmtu_mode == 2 : quote.hard))
                socket.error = quote.error;
        }
    }
    if (!udp)
        return;
    bool hard = quote.hard;
    if (quote.type == 2) {
        if (udp->pmtu_mode >= 4)
            return;
        learn(udp->index, udp);
        hard = udp->pmtu_mode != 0;
    }
    enqueue(*udp);
    if (udp->receive_errors || (hard && udp->connected))
        udp->error = quote.error;
}
} // namespace ax

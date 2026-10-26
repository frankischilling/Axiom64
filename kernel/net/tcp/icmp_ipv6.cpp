// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/socket.hpp"
#include "net/tcp/connection.hpp"
#include "net/ipv6/host.hpp"
#include "net/ipv6/icmp.hpp"
#include "net/ipv4_wire.hpp"
#include "../ipv4/socket.hpp"

namespace ax {
bool tcp6_path_mtu(InetSocket* socket, size_t failed_bytes) {
    if (!socket || !socket->used || !socket->wire6 || !socket->stream)
        return false;
    Ipv6Path path;
    if (ipv6_path(socket->local6, socket->peer6, socket->index, path, false,
                  tcp6_source_policy(socket)) ||
        path.mtu < ip6::minimum_mtu)
        return false;
    uint16_t limit = uint16_t(min(path.mtu - 60, 1460u));
    bool dropped = failed_bytes > path.mtu;
    if (socket->stream->path_mss(limit, dropped))
        ipv6_discard_oversized(socket, path.mtu);
    return dropped && socket->stream->segment_size() <= limit;
}

void tcp6_icmp_error(unsigned index, const ip6::ErrorQuote& quote) {
    if (quote.protocol != 6 || quote.length < 8)
        return;
    uint16_t source = ip4::get16(quote.transport);
    uint16_t destination = ip4::get16(quote.transport + 2);
    uint32_t sequence = ip4::get32(quote.transport + 4);
    for (auto& socket : inet_sockets) {
        if (!socket.used || !socket.wire6 || socket.type != 1 || !socket.stream ||
            socket.listening || socket.local6 != quote.source ||
            socket.peer6 != quote.transport_destination || socket.local_port != source ||
            __builtin_bswap16(socket.peer_port) != destination ||
            (socket.index && socket.index != index))
            continue;
        if (quote.type != 2) {
            socket.stream->quoted_error(sequence, quote.error, quote.hard);
            continue;
        }
        if (quote.information < ip6::minimum_mtu || !socket.stream->owns_pmtu_quote(sequence, true))
            continue;
        // A hint which cannot lower the effective peer/path MSS must not create
        // a shared route exception. Idle established streams can still own the
        // inclusive SND.NXT quote, without manufacturing a retransmission.
        if (quote.information - 60 >= socket.stream->segment_size())
            continue;
        Ipv6Path path;
        if (ipv6_path(quote.source, quote.destination, socket.index, path, true,
                      tcp6_source_policy(&socket)))
            continue;
        uint32_t mtu = ip6::path_mtu_cache.learn(ip6::path_key(path, quote.destination), path.mtu,
                                                 quote.information, ticks);
        uint16_t limit = uint16_t(min(mtu - 60, 1460u));
        if (socket.stream->path_mss(limit, true))
            ipv6_discard_oversized(&socket, mtu);
    }
}
} // namespace ax

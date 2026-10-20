// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket.hpp"

namespace ax {
Inet6Socket inet6_sockets[inet6_socket_count];
static uint16_t next_port = 32768;
static uint64_t binding_order;

Inet6Socket* inet6_allocate(unsigned type) {
    for (auto& socket : inet6_sockets)
        if (!socket.used) {
            socket = {};
            socket.used = true;
            socket.type = type;
            socket.protocol = type == 2 ? 17 : 58;
            socket.reuse = type == 3;
            return &socket;
        }
    return nullptr;
}

const Inet6Frame* inet6_front(Inet6Socket* socket) {
    return socket->count ? socket->queue[socket->head] : nullptr;
}

void inet6_consume(Inet6Socket* socket) {
    if (!socket->count)
        return;
    auto& frame = socket->queue[socket->head];
    socket->bytes -= frame->length;
    release(frame);
    frame = nullptr;
    socket->head = (socket->head + 1) % inet6_queue_count;
    socket->count--;
}

void inet6_close(Inet6Socket* socket) {
    ipv6_detach_owner(socket);
    while (socket->count)
        inet6_consume(socket);
    socket->used = false;
}

int inet6_error(Inet6Socket* socket, bool clear) {
    if (socket->index && socket->index != ipv6_loopback) {
        auto info = net_info(socket->index);
        if (!info || !info->live)
            return 5;
    }
    int result = socket->error;
    if (clear)
        socket->error = 0;
    return result;
}

unsigned inet6_shutdown(Inet6Socket* socket) {
    return socket->shutdown;
}

size_t inet6_available(Inet6Socket* socket) {
    auto frame = inet6_front(socket);
    return frame ? frame->length : 0;
}

bool inet6_ready(Inet6Socket* socket, bool write) {
    return inet6_error(socket) ||
           (write ? (socket->shutdown & 2) ||
                        (ipv6_output_ready() && socket->transmitted < socket->send_limit)
                  : (socket->shutdown & 1) || socket->count);
}

void inet6_complete(Inet6Socket* socket, size_t bytes, int error) {
    if (!socket || !socket->used)
        return;
    socket->transmitted -= min(socket->transmitted, bytes);
    if (error && socket->connected && !socket->error)
        socket->error = -error;
}

Inet6Address inet6_peer(Inet6Socket* socket) {
    return {10, socket->peer_port, 0, socket->peer, socket->peer.link_local() ? socket->index : 0};
}

int inet6_target(Inet6Socket* socket, Inet6Address& address, bool named, uint32_t imported_length) {
    if (named && (imported_length < (socket->type == 3 ? 24u : 2u) || imported_length > 128 ||
                  (address.family == 10 && imported_length < 24)))
        return -22;
    if (named && !address.family) {
        if (socket->type == 2) {
            address = inet6_peer(socket);
            named = false;
        } else
            address.family = 10;
    }
    if (address.family != 10)
        return !named ? -89 : socket->type == 2 && address.family != 2 ? -22 : -97;
    if (!named && !socket->connected)
        return -89;
    if (socket->type == 2 && !address.port)
        return -22;
    if (named && socket->type == 3 && address.port &&
        __builtin_bswap16(address.port) != socket->protocol)
        return -22;
    if (address.address.unspecified())
        address.address.bytes[15] = 1;
    if (address.address.mapped())
        return -101;
    return 0;
}

int inet6_bind_port(Inet6Socket* socket, const ip6::Address& local, uint16_t port) {
    auto conflict = [&](uint16_t candidate) {
        for (auto& other : inet6_sockets)
            if (other.used && &other != socket && other.type == 2 &&
                other.local_port == candidate &&
                (!other.index || !socket->index || other.index == socket->index) &&
                (local.unspecified() || other.local.unspecified() || local == other.local) &&
                (!other.reuse || !socket->reuse))
                return true;
        return false;
    };
    if (port && conflict(port))
        return -98;
    if (!port) {
        for (unsigned attempt = 0; attempt <= inet6_socket_count; attempt++) {
            auto candidate = next_port;
            next_port = candidate == 60999 ? 32768 : candidate + 1;
            if (!conflict(candidate)) {
                port = candidate;
                break;
            }
        }
        if (!port)
            return -11;
    }
    socket->local_port = port;
    socket->order = ++binding_order;
    return 0;
}

static void enqueue(Inet6Socket& socket, unsigned index, const ip6::Address& source, uint16_t port,
                    const void* data, size_t length) {
    if (socket.count == inet6_queue_count ||
        length > socket.receive_limit - min(socket.bytes, size_t(socket.receive_limit)))
        return;
    auto frame = static_cast<Inet6Frame*>(alloc(sizeof(Inet6Frame) + length));
    if (!frame)
        return;
    *frame = {{10, __builtin_bswap16(port), 0, source, source.link_local() ? index : 0}, length};
    memcpy(frame + 1, data, length);
    socket.queue[(socket.head + socket.count) % inet6_queue_count] = frame;
    socket.count++;
    socket.bytes += length;
}

bool inet6_deliver(unsigned index, const ip6::Packet& packet) {
    bool datagram = packet.protocol == 17;
    auto data = packet.payload;
    size_t length = packet.length;
    if ((!datagram && packet.protocol != 58) || length < (datagram ? 8u : 4u))
        return true;
    uint16_t source_port = 0, destination_port = 0;
    if (datagram) {
        size_t declared = size_t(data[4]) << 8 | data[5];
        if ((!data[6] && !data[7]) || declared < 8 || declared > length)
            return true;
        if (ip6::checksum(packet.header.source, packet.header.destination, 17, data, declared))
            return true;
        source_port = uint16_t(data[0]) << 8 | data[1];
        destination_port = uint16_t(data[2]) << 8 | data[3];
        length = declared - 8;
        data += 8;
    } else {
        if (ip6::checksum(packet.header.source, packet.header.destination, 58, data, length))
            return true;
        if (data[0] == 1 && data[1] == 4 && length >= 56 && (data[8] >> 4) == 6 &&
            (data[14] == 17 || data[14] == 58) && (data[12] || data[13] >= 8)) {
            ip6::Address local, peer;
            memcpy(local.bytes, data + 16, 16);
            memcpy(peer.bytes, data + 32, 16);
            for (auto& socket : inet6_sockets)
                if (socket.used && socket.connected && socket.local == local &&
                    socket.peer == peer &&
                    (!socket.index || socket.index == index || index == ipv6_loopback) &&
                    socket.protocol == data[14] &&
                    (socket.type == 3 ||
                     (socket.local_port == (uint16_t(data[48]) << 8 | data[49]) &&
                      socket.peer_port == (uint16_t(data[51]) << 8 | data[50]))) &&
                    !socket.error)
                    socket.error = 111;
        }
    }
    Inet6Socket* best = nullptr;
    unsigned best_score = 0;
    bool matched = false;
    for (auto& socket : inet6_sockets) {
        if (!socket.used || socket.type != (datagram ? 2 : 3) ||
            (socket.index && socket.index != index && index != ipv6_loopback) ||
            (!socket.local.unspecified() && !(socket.local == packet.header.destination)) ||
            (socket.connected && !(socket.peer == packet.header.source)) ||
            (datagram &&
             (socket.local_port != destination_port || !socket.local_port ||
              (socket.connected && socket.peer_port != __builtin_bswap16(source_port)))) ||
            (!datagram && (socket.filter[data[0] / 32] & (uint32_t(1) << (data[0] % 32)))))
            continue;
        matched = true;
        if (!datagram || packet.header.destination.multicast()) {
            enqueue(socket, index, packet.header.source, source_port, data, length);
            continue;
        }
        unsigned score = (!socket.local.unspecified() ? 4 : 0) + (socket.connected ? 8 : 0) +
                         (socket.index ? 4 : 0);
        if (!best || score > best_score || (score == best_score && socket.order > best->order)) {
            best = &socket;
            best_score = score;
        }
    }
    if (best)
        enqueue(*best, index, packet.header.source, source_port, data, length);
    return matched;
}

int64_t inet6_send(Inet6Socket* socket, const Inet6Address& requested, const void* data,
                   size_t length, bool named) {
    if (int error = inet6_error(socket, true))
        return -error;
    if (socket->shutdown & 2)
        return -32;
    auto address = requested;
    if (int error = inet6_target(socket, address, named))
        return error;
    size_t overhead = ip6::header_size + (socket->type == 2 ? 8 : 0);
    if (length > 65535 - (overhead - ip6::header_size) || length + overhead > socket->send_limit)
        return -90;
    if (length + overhead >
        socket->send_limit - min(socket->transmitted, size_t(socket->send_limit)))
        return -11;
    unsigned index = address.address.link_local() && address.scope ? address.scope : socket->index;
    Ipv6Path path;
    int error = ipv6_path(socket->local, address.address, index, path);
    if (error)
        return error;
    if (length + overhead > path.mtu)
        return -90;
    size_t size = length + overhead - ip6::header_size;
    if (socket->type == 3 && size < 4)
        return -22;
    auto bytes = static_cast<uint8_t*>(alloc(size));
    if (!bytes)
        return -12;
    size_t offset = socket->type == 2 ? 8 : 0;
    memcpy(bytes + offset, data, length);
    if (socket->type == 2) {
        if (!socket->local_port) {
            error = inet6_bind_port(socket, socket->local, 0);
            if (error) {
                release(bytes);
                return error;
            }
        }
        bytes[0] = socket->local_port >> 8;
        bytes[1] = socket->local_port;
        memcpy(bytes + 2, &address.port, 2);
        bytes[4] = size >> 8;
        bytes[5] = size;
    }
    unsigned check_at = socket->type == 2 ? 6 : 2;
    bytes[check_at] = bytes[check_at + 1] = 0;
    uint16_t checksum = ip6::checksum(path.source, address.address, socket->protocol, bytes, size);
    if (!checksum && socket->type == 2)
        checksum = 0xffff;
    bytes[check_at] = checksum >> 8;
    bytes[check_at + 1] = checksum;
    error = ipv6_send(path.source, address.address, index, socket->protocol, socket->hops, bytes,
                      size, socket);
    release(bytes);
    if (!error)
        socket->transmitted += length + overhead;
    return error ? error : int64_t(length);
}

int64_t inet6_read(Inet6Socket* socket, void* data, size_t capacity) {
    if (int error = inet6_error(socket, true))
        return -error;
    auto frame = inet6_front(socket);
    if (!frame)
        return -11;
    size_t copied = min(capacity, frame->length);
    memcpy(data, inet6_bytes(frame), copied);
    inet6_consume(socket);
    return copied;
}
} // namespace ax

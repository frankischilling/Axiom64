// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/netlink/socket.cpp
 * @brief   Netlink socket transport.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Queues requests and responses and maintains netlink socket addressing and
 * readiness.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "net/netlink.hpp"
#include "net/socket_control.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr unsigned socket_count = 64, queue_count = 32;
constexpr size_t queue_bytes = 65536;
constexpr size_t max_buffer_request = 512 * 1024;
constexpr unsigned route_protocol = 0, generic_protocol = 16;
uint32_t next_port = UINT32_MAX;

size_t aligned(size_t size) {
    return (size + 3) & ~size_t(3);
}
} // namespace

struct NetlinkSocket {
    bool used = false, capped = false, strict = false, passcred = false;
    unsigned protocol = route_protocol;
    unsigned type = 3, head = 0, count = 0;
    unsigned deliveries = 0;
    uint32_t port = 0;
    uint64_t groups = 0;
    size_t bytes = 0, receive_limit = queue_bytes, send_limit = queue_bytes;
    NetlinkFrame* queue[queue_count]{};
};

namespace {
NetlinkSocket sockets[socket_count];

bool occupied(unsigned protocol, uint32_t port) {
    for (const auto& socket : sockets)
        if (socket.used && socket.protocol == protocol && socket.port == port)
            return true;
    return false;
}

int bind_port(NetlinkSocket* socket, uint32_t port, unsigned process) {
    if (socket->port)
        return port == socket->port ? 0 : -22;
    if (!port) {
        port = process;
        for (unsigned attempt = 0; occupied(socket->protocol, port) && attempt < socket_count;
             attempt++) {
            port = next_port--;
            if (!next_port)
                next_port = UINT32_MAX;
        }
    }
    if (!port || occupied(socket->protocol, port))
        return -98;
    socket->port = port;
    return 0;
}

int address_out(Task& task, const NetlinkAddress& address, uint64_t output, uint64_t count) {
    uint32_t capacity, actual = sizeof(address);
    if (!task.memory->space.copy_in(&capacity, count, 4) ||
        !task.memory->space.copy_out(output, &address, min(capacity, actual)) ||
        !task.memory->space.copy_out(count, &actual, 4))
        return -14;
    return 0;
}
} // namespace

int netlink_target(const NetlinkAddress& address) {
    if (address.family != 16)
        return -22;
    if (address.groups)
        return -95;
    return address.port ? -111 : 0;
}

void netlink_consume(NetlinkSocket* socket) {
    if (!socket->count)
        return;
    auto& frame = socket->queue[socket->head];
    socket->bytes -= frame->reserved;
    release(frame);
    frame = nullptr;
    socket->head = (socket->head + 1) % queue_count;
    socket->count--;
}

void netlink_close(NetlinkSocket* socket) {
    while (socket->count)
        netlink_consume(socket);
    *socket = {};
}

const NetlinkFrame* netlink_front(NetlinkSocket* socket) {
    return socket->count ? socket->queue[socket->head] : nullptr;
}

size_t netlink_receive_control(Task& task, NetlinkSocket* socket, uint64_t address,
                               uint64_t capacity, uint32_t& flags) {
    if (!socket->passcred)
        return 0;
    // Both protocols emit kernel-generated responses.
    constexpr uint32_t credentials[3]{};
    SocketControlWriter writer(task, 1, address, capacity, flags);
    writer.append(2, credentials, sizeof(credentials)); // SCM_CREDENTIALS.
    return writer.used;
}

size_t netlink_available(NetlinkSocket* socket) {
    auto frame = netlink_front(socket);
    return frame ? frame->length : 0;
}

bool netlink_ready(NetlinkSocket* socket, bool write) {
    return write ? socket->count + socket->deliveries < queue_count &&
                       socket->bytes + netlink_ack_size <= socket->receive_limit
                 : socket->count != 0;
}

int netlink_reserve_delivery(NetlinkSocket* socket, size_t length, NetlinkFrame*& frame) {
    // POSIX message queues use route sockets for completion cookies.
    if (socket->protocol != route_protocol)
        return -95;
    if (socket->count + socket->deliveries >= queue_count ||
        socket->bytes + length > socket->receive_limit)
        return -11;
    frame = static_cast<NetlinkFrame*>(alloc(sizeof(NetlinkFrame) + length));
    if (!frame)
        return -12;
    frame->source = {};
    frame->length = frame->reserved = length;
    ++socket->deliveries;
    socket->bytes += length;
    return 0;
}

void netlink_publish_delivery(NetlinkSocket* socket, NetlinkFrame* frame) {
    --socket->deliveries;
    socket->queue[(socket->head + socket->count++) % queue_count] = frame;
}

int64_t netlink_read(NetlinkSocket* socket, void* output, size_t length) {
    auto frame = netlink_front(socket);
    if (!frame)
        return -11;
    size_t copied = min(length, frame->length);
    memcpy(output, netlink_bytes(frame), copied);
    netlink_consume(socket);
    return copied;
}

int64_t netlink_send(Task& task, NetlinkSocket* socket, const void* data, size_t length) {
    if (length > netlink_max_request || length > socket->send_limit - 32)
        return -90;
    if (!length)
        return -61;
    auto bytes = static_cast<const uint8_t*>(data);

    struct Reply {
        size_t position, capacity;
        bool followup;
        NetlinkFrame *data, *end;
    };

    Reply replies[queue_count]{};
    size_t count = 0, frames = 0, total = 0;
    const bool generic = socket->protocol == generic_protocol;
    // Reserve every response before processing the first request in this datagram.
    // No route mutation can succeed while allocation/backpressure loses its result.
    for (size_t at = 0; at < length;) {
        NetlinkHeader header;
        if (length - at < sizeof(header))
            return -22;
        memcpy(&header, bytes + at, sizeof(header));
        if (header.length < sizeof(header) || header.length > length - at)
            return -22;
        if (count == queue_count)
            return -90;
        auto& reply = replies[count++];
        reply.position = at;
        if (generic) {
            const size_t error_size =
                socket->capped ? netlink_ack_size : 20 + aligned(header.length);
            reply.capacity = max(generic_family_reply_size, error_size);
            reply.followup = (header.flags & 4) || (header.flags & 0x300) == 0x300;
        } else {
            reply.capacity = socket->capped && !routing_dump(header.type)
                                 ? netlink_ack_size
                                 : routing_capacity(header, bytes + at);
        }
        frames += reply.followup ? 2 : 1;
        total += reply.capacity + (reply.followup ? netlink_ack_size : 0);
        if (header.length == length - at)
            break;
        if (aligned(header.length) > length - at)
            return -22;
        at += aligned(header.length);
    }
    if (frames > queue_count || total > socket->receive_limit)
        return -90;
    if (frames > queue_count - socket->count - socket->deliveries ||
        socket->bytes + total > socket->receive_limit)
        return -11;
    int error = socket->port ? 0 : bind_port(socket, 0, task.process->pid);
    if (error)
        return error;
    for (size_t i = 0; i < count; i++) {
        auto& reply = replies[i];
        reply.data = static_cast<NetlinkFrame*>(alloc(sizeof(NetlinkFrame) + reply.capacity));
        if (reply.data && reply.followup)
            reply.end = static_cast<NetlinkFrame*>(alloc(sizeof(NetlinkFrame) + netlink_ack_size));
        if (reply.data && (!reply.followup || reply.end))
            continue;
        for (size_t j = 0; j <= i; j++) {
            release(replies[j].data);
            release(replies[j].end);
        }
        return -12;
    }
    const auto publish = [socket](NetlinkFrame* frame, size_t reserved, size_t size) {
        if (!size) {
            release(frame);
            return;
        }
        frame->source = {};
        frame->reserved = reserved;
        frame->length = size;
        socket->queue[(socket->head + socket->count++) % queue_count] = frame;
        socket->bytes += reserved;
    };
    for (size_t i = 0; i < count; i++) {
        const auto& reply = replies[i];
        const auto* input = bytes + reply.position;
        size_t tail = 0;
        size_t size = generic ? generic_reply(input, socket->port, socket->capped, reply.data + 1,
                                              reply.end ? reply.end + 1 : nullptr, tail)
                              : routing_reply(input, socket->port, socket->capped, reply.data + 1,
                                              capable(task.credentials, Capability::net_admin),
                                              socket->strict);
        publish(reply.data, reply.capacity, size);
        if (reply.end)
            publish(reply.end, netlink_ack_size, tail);
    }
    return length;
}

int64_t netlink_syscall(Task& task, const Frame& frame) {
    auto a = frame.rdi, b = frame.rsi, c = frame.rdx, d = frame.r10;
    auto handle = a < max_fds ? task.files->entries[a].handle : nullptr;
    auto socket = handle ? handle->netlink : nullptr;
    if (frame.rax == 41) {
        if ((b & 0xf) != 2 && (b & 0xf) != 3)
            return -94;
        if (b & ~uint64_t(0x8080f))
            return -22;
        if (c != route_protocol && c != generic_protocol)
            return -93;
        socket = nullptr;
        for (auto& candidate : sockets)
            if (!candidate.used) {
                socket = &candidate;
                break;
            }
        if (!socket)
            return -23;
        *socket = {};
        socket->used = true;
        socket->type = b & 0xf;
        socket->protocol = c;
        auto opened = open_handle(nullptr, 2 | ((b & 0x800) ? 04000 : 0));
        if (!opened) {
            netlink_close(socket);
            return -23;
        }
        opened->netlink = socket;
        int fd = allocate_fd(&task, opened, 0, b & 0x80000);
        if (fd < 0)
            close_handle(opened);
        return fd;
    }
    if (!socket)
        return -88;
    if (frame.rax == 49 || frame.rax == 42) {
        NetlinkAddress address;
        if (c < sizeof(address))
            return -22;
        if (!task.memory->space.copy_in(&address, b, sizeof(address)))
            return -14;
        if (address.family != 16)
            return -22;
        if (frame.rax == 49) {
            int error = bind_port(socket, address.port, task.process->pid);
            if (!error)
                socket->groups = (socket->groups & ~uint64_t(UINT32_MAX)) | address.groups;
            return error;
        }
        if (int error = netlink_target(address))
            return error;
        if (int error = socket->port ? 0 : bind_port(socket, 0, task.process->pid))
            return error;
        return 0;
    }
    if (frame.rax == 51 || frame.rax == 52) {
        NetlinkAddress address;
        if (frame.rax == 51) {
            address.port = socket->port;
            address.groups = socket->groups;
        }
        return address_out(task, address, b, c);
    }
    if (frame.rax == 54) {
        int value;
        if (frame.r8 < 4)
            return -22;
        if (!task.memory->space.copy_in(&value, d, 4))
            return -14;
        if (b == 270 && c == 10)
            socket->capped = value != 0;
        else if (b == 270 && c == 12)
            socket->strict = value != 0;
        else if (b == 270 && (c == 1 || c == 2)) {
            if (value < 1 || value > 64)
                return -22;
            const uint64_t group = uint64_t{1} << (value - 1);
            if (c == 1)
                socket->groups |= group;
            else
                socket->groups &= ~group;
        } else if (b == 1 && (c == 7 || c == 8)) {
            size_t limit = 2 * min(size_t(uint32_t(value)), max_buffer_request);
            if (c == 7)
                socket->send_limit = max(size_t(2048), limit);
            else
                socket->receive_limit = max(size_t(4096), limit);
        } else if (b == 1 && c == 16)
            socket->passcred = value != 0;
        else
            return -92;
        return 0;
    }
    if (frame.rax == 55) {
        uint32_t value, capacity, actual = 4;
        if (b == 270 && (c == 10 || c == 12))
            value = c == 10 ? socket->capped : socket->strict;
        else if (b == 1 && c == 3)
            value = socket->type;
        else if (b == 1 && c == 4)
            value = 0;
        else if (b == 1 && c == 38)
            value = socket->protocol;
        else if (b == 1 && c == 39)
            value = 16;
        else if (b == 1 && c == 7)
            value = socket->send_limit;
        else if (b == 1 && c == 8)
            value = socket->receive_limit;
        else if (b == 1 && c == 16)
            value = socket->passcred;
        else
            return -92;
        if (!task.memory->space.copy_in(&capacity, frame.r8, 4))
            return -14;
        if (int32_t(capacity) < 0 || (b == 270 && capacity < 4))
            return -22;
        if (!task.memory->space.copy_out(d, &value, min(capacity, actual)) ||
            !task.memory->space.copy_out(frame.r8, &actual, 4))
            return -14;
        return 0;
    }
    return -95;
}
} // namespace ax

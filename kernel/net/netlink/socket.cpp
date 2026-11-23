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
#include "ipc/ipc.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr unsigned socket_count = 64, queue_count = 32;
constexpr size_t queue_bytes = 65536;
constexpr unsigned routing_protocol = 0, uevent_protocol = 15;
constexpr uint32_t kernel_uevent_group = 1;
uint32_t next_port = UINT32_MAX;

size_t aligned(size_t size) {
    return (size + 3) & ~size_t(3);
}
} // namespace

struct NetlinkSocket {
    bool used = false, connected = false, capped = false, strict = false;
    bool passcred = false;
    unsigned protocol = routing_protocol, type = 3, head = 0, count = 0;
    unsigned deliveries = 0;
    uint32_t port = 0, groups = 0;
    size_t bytes = 0, byte_limit = queue_bytes;
    int error = 0;
    Handle* handle = nullptr;
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

size_t netlink_available(NetlinkSocket* socket) {
    auto frame = netlink_front(socket);
    return frame ? frame->length : 0;
}

bool netlink_ready(NetlinkSocket* socket, bool write) {
    return write ? socket->count + socket->deliveries < queue_count &&
                       socket->bytes + 36 <= queue_bytes
                 : socket->count != 0 || socket->error;
}

int netlink_error(NetlinkSocket* socket, bool consume) {
    const int error = socket->error;
    if (consume)
        socket->error = 0;
    return error;
}

static int reserve_frame(NetlinkSocket* socket, size_t length, NetlinkFrame*& frame) {
    if (socket->count + socket->deliveries >= queue_count || socket->bytes > socket->byte_limit ||
        length > socket->byte_limit - socket->bytes)
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

int netlink_reserve_delivery(NetlinkSocket* socket, size_t length, NetlinkFrame*& frame) {
    // POSIX message queues use route sockets for completion cookies. Those
    // cookies must never enter a kernel device event stream.
    if (socket->protocol != routing_protocol)
        return -95;
    return reserve_frame(socket, length, frame);
}

void netlink_publish_delivery(NetlinkSocket* socket, NetlinkFrame* frame) {
    --socket->deliveries;
    socket->queue[(socket->head + socket->count++) % queue_count] = frame;
}

void netlink_broadcast_uevent(const void* data, size_t length) {
    for (auto& socket : sockets) {
        if (!socket.used || socket.protocol != uevent_protocol ||
            !(socket.groups & kernel_uevent_group))
            continue;
        NetlinkFrame* frame;
        if (reserve_frame(&socket, length, frame)) {
            socket.error = 105; // ENOBUFS: the listener lost at least one datagram.
            epoll_notify(socket.handle, 8);
            continue;
        }
        frame->source.groups = kernel_uevent_group;
        memcpy(frame + 1, data, length);
        netlink_publish_delivery(&socket, frame);
        epoll_notify(socket.handle, 1);
    }
}

size_t netlink_receive_control(Task& task, NetlinkSocket* socket, uint64_t address,
                               uint64_t capacity, uint32_t& flags) {
    if (socket->protocol != uevent_protocol || !socket->passcred)
        return 0;
    SocketControlWriter output(task, 1, address, capacity, flags); // SOL_SOCKET.
    constexpr uint32_t credentials[3]{};                           // Kernel pid, uid and gid.
    output.append(2, credentials, sizeof(credentials));            // SCM_CREDENTIALS.
    return output.used;
}

int64_t netlink_read(NetlinkSocket* socket, void* output, size_t length) {
    if (int error = netlink_error(socket, true))
        return -error;
    auto frame = netlink_front(socket);
    if (!frame)
        return -11;
    size_t copied = min(length, frame->length);
    memcpy(output, netlink_bytes(frame), copied);
    netlink_consume(socket);
    return copied;
}

int64_t netlink_send(Task& task, NetlinkSocket* socket, const void* data, size_t length) {
    if (socket->protocol != routing_protocol)
        return -95;
    if (length > netlink_max_request)
        return -90;
    if (!length)
        return -61;
    auto bytes = static_cast<const uint8_t*>(data);
    size_t positions[queue_count]{}, capacities[queue_count]{}, count = 0, total = 0;
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
        positions[count] = at;
        capacities[count] = socket->capped && !routing_dump(header.type)
                                ? 36
                                : routing_capacity(header, bytes + at);
        total += capacities[count++];
        if (header.length == length - at)
            break;
        if (aligned(header.length) > length - at)
            return -22;
        at += aligned(header.length);
    }
    if (total > queue_bytes)
        return -90;
    if (count > queue_count - socket->count - socket->deliveries ||
        total > queue_bytes - socket->bytes)
        return -11;
    int error = socket->port ? 0 : bind_port(socket, 0, task.process->pid);
    if (error)
        return error;
    NetlinkFrame* replies[queue_count]{};
    for (size_t i = 0; i < count; i++) {
        replies[i] = static_cast<NetlinkFrame*>(alloc(sizeof(NetlinkFrame) + capacities[i]));
        if (!replies[i]) {
            for (size_t j = 0; j < i; j++)
                release(replies[j]);
            return -12;
        }
    }
    for (size_t i = 0; i < count; i++) {
        auto reply = replies[i];
        reply->source = {};
        reply->reserved = capacities[i];
        reply->length =
            routing_reply(bytes + positions[i], socket->port, socket->capped, reply + 1,
                          capable(task.credentials, Capability::net_admin), socket->strict);
        if (!reply->length) {
            release(reply);
            continue;
        }
        socket->queue[(socket->head + socket->count) % queue_count] = reply;
        socket->count++;
        socket->bytes += reply->reserved;
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
        if (c != routing_protocol && c != uevent_protocol)
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
        socket->handle = opened;
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
            const uint32_t allowed = socket->protocol == uevent_protocol ? kernel_uevent_group : 0;
            if (address.groups & ~allowed)
                return -95;
            if (int error = bind_port(socket, address.port, task.process->pid))
                return error;
            socket->groups = address.groups;
            return 0;
        }
        if (int error = netlink_target(address))
            return error;
        if (int error = socket->port ? 0 : bind_port(socket, 0, task.process->pid))
            return error;
        socket->connected = true;
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
        if (socket->protocol == uevent_protocol && b == 1 && c == 16) // SO_PASSCRED.
            socket->passcred = value != 0;
        else if (socket->protocol == uevent_protocol && b == 1 && (c == 8 || c == 33)) {
            if (c == 33 && !capable(task.credentials, Capability::net_admin))
                return -1;
            if (value < 0)
                return -22;
            socket->byte_limit = max(size_t(256), min(size_t(value) * 2, queue_bytes));
        } else if (socket->protocol == uevent_protocol && b == 270 && (c == 1 || c == 2)) {
            if (value != 1)
                return -22;
            socket->groups = c == 1 ? kernel_uevent_group : 0;
        } else if (b == 270 && c == 10)
            socket->capped = value != 0;
        else if (b == 270 && c == 12)
            socket->strict = value != 0;
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
            value = netlink_error(socket);
        else if (b == 1 && c == 16 && socket->protocol == uevent_protocol)
            value = socket->passcred;
        else if (b == 1 && c == 38)
            value = socket->protocol;
        else if (b == 1 && c == 39)
            value = 16;
        else if (b == 1 && c == 8)
            value = socket->byte_limit;
        else if (b == 1 && c == 7)
            value = queue_bytes;
        else
            return -92;
        if (!task.memory->space.copy_in(&capacity, frame.r8, 4))
            return -14;
        if (int32_t(capacity) < 0 || (b == 270 && capacity < 4))
            return -22;
        if (!task.memory->space.copy_out(d, &value, min(capacity, actual)) ||
            !task.memory->space.copy_out(frame.r8, &actual, 4))
            return -14;
        if (b == 1 && c == 4)
            netlink_error(socket, true);
        return 0;
    }
    return -95;
}
} // namespace ax

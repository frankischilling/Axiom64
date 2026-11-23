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
#include "ipc/ipc.hpp"
#include "net/socket_filter.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr unsigned socket_count = 64, queue_count = 32;
constexpr size_t queue_bytes = 65536;
constexpr unsigned device_events = 15, kernel_group = 1, userspace_group = 2;
constexpr unsigned device_groups = kernel_group | userspace_group;
uint32_t next_port = UINT32_MAX;

size_t aligned(size_t size) {
    return (size + 3) & ~size_t(3);
}
} // namespace

struct NetlinkSocket {
    bool used = false, connected = false, capped = false, strict = false;
    bool pass_credentials = false, overrun = false;
    unsigned type = 3, head = 0, count = 0;
    unsigned protocol = 0;
    unsigned deliveries = 0;
    uint32_t port = 0, groups = 0;
    SocketFilter filter{};
    size_t bytes = 0;
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

int netlink_target(const NetlinkSocket* socket, const NetlinkAddress& address) {
    if (address.family != 16)
        return -22;
    if (address.groups && (socket->protocol != device_events || address.groups != userspace_group))
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
    socket->filter.clear();
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
                 : socket->count != 0 || socket->overrun;
}

bool netlink_pass_credentials(const NetlinkSocket* socket) {
    return socket->pass_credentials;
}

bool netlink_overrun(const NetlinkSocket* socket) {
    return socket->overrun;
}

bool netlink_take_overrun(NetlinkSocket* socket) {
    const bool overrun = socket->overrun;
    socket->overrun = false;
    return overrun;
}

int netlink_reserve_delivery(NetlinkSocket* socket, size_t length, NetlinkFrame*& frame) {
    if (socket->count + socket->deliveries >= queue_count || length > queue_bytes - socket->bytes)
        return -11;
    frame = static_cast<NetlinkFrame*>(alloc(sizeof(NetlinkFrame) + length));
    if (!frame)
        return -12;
    frame->source = {};
    frame->credentials = {};
    frame->length = frame->reserved = length;
    ++socket->deliveries;
    socket->bytes += length;
    return 0;
}

void netlink_publish_delivery(NetlinkSocket* socket, NetlinkFrame* frame) {
    --socket->deliveries;
    socket->queue[(socket->head + socket->count++) % queue_count] = frame;
}

static void multicast_device_event(const NetlinkSocket* sender, const NetlinkAddress& source,
                                   const UnixMessageCredentials& identity, const void* data,
                                   size_t length) {
    for (auto& socket : sockets) {
        if (!socket.used || &socket == sender || socket.protocol != device_events ||
            !(socket.groups & source.groups))
            continue;
        const size_t accepted = socket.filter.accept(data, length);
        if (!accepted)
            continue;
        NetlinkFrame* frame;
        if (netlink_reserve_delivery(&socket, accepted, frame)) {
            if (!socket.overrun) {
                socket.overrun = true;
                epoll_notify_source(&socket, 8);
            }
            continue;
        }
        frame->source = source;
        frame->credentials = identity;
        memcpy(frame + 1, data, accepted);
        netlink_publish_delivery(&socket, frame);
        epoll_notify_source(&socket, 1);
    }
}

void netlink_device_event(const void* data, size_t length) {
    multicast_device_event(nullptr, {.groups = kernel_group}, UnixMessageCredentials::kernel(),
                           data, length);
}

int64_t netlink_read(NetlinkSocket* socket, void* output, size_t length) {
    if (netlink_take_overrun(socket))
        return -105;
    auto frame = netlink_front(socket);
    if (!frame)
        return -11;
    size_t copied = min(length, frame->length);
    memcpy(output, netlink_bytes(frame), copied);
    netlink_consume(socket);
    return copied;
}

int64_t netlink_send(Task& task, NetlinkSocket* socket, const void* data, size_t length,
                     const NetlinkAddress& destination) {
    if (length > netlink_max_request)
        return -90;
    if (socket->protocol == device_events) {
        if (destination.groups != userspace_group || destination.port)
            return -95;
        if (!capable(task.credentials, Capability::net_admin))
            return -1;
        if (!length)
            return -61;
        if (!socket->port)
            if (int error = bind_port(socket, 0, task.process->pid))
                return error;
        UnixMessageCredentials identity;
        identity.capture(task);
        multicast_device_event(socket, {.port = socket->port, .groups = userspace_group}, identity,
                               data, length);
        return length;
    }
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
        reply->credentials = {};
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
        if (c && c != device_events)
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
            if (address.groups &&
                (socket->protocol != device_events || (address.groups & ~device_groups)))
                return -95;
            int error = bind_port(socket, address.port, task.process->pid);
            if (!error)
                socket->groups = address.groups;
            return error;
        }
        if (address.groups)
            return -95;
        if (int error = netlink_target(socket, address))
            return error;
        if (int error = socket->port ? 0 : bind_port(socket, 0, task.process->pid))
            return error;
        socket->connected = true;
        return 0;
    }
    if (frame.rax == 51 || frame.rax == 52) {
        NetlinkAddress address;
        address.port = frame.rax == 51 ? socket->port : 0;
        address.groups = frame.rax == 51 ? socket->groups : 0;
        return address_out(task, address, b, c);
    }
    if (frame.rax == 54) {
        if (socket->protocol == device_events && b == 1 && c == 26)
            return socket->filter.install(task, d, frame.r8);
        if (socket->protocol == device_events && b == 1 && c == 27) {
            if (!socket->filter.instructions)
                return -2;
            socket->filter.clear();
            return 0;
        }
        int value;
        if (frame.r8 < 4)
            return -22;
        if (!task.memory->space.copy_in(&value, d, 4))
            return -14;
        if (socket->protocol == device_events && b == 1 && c == 16)
            socket->pass_credentials = value != 0;
        else if (socket->protocol == device_events && b == 270 && (c == 1 || c == 2)) {
            if (value < 1 || value > 2)
                return -22;
            const unsigned group = 1u << (value - 1);
            if (c == 1)
                socket->groups |= group;
            else
                socket->groups &= ~group;
        } else if (!socket->protocol && b == 270 && c == 10)
            socket->capped = value != 0;
        else if (!socket->protocol && b == 270 && c == 12)
            socket->strict = value != 0;
        else
            return -92;
        return 0;
    }
    if (frame.rax == 55) {
        uint32_t value, capacity, actual = 4;
        if (!socket->protocol && b == 270 && (c == 10 || c == 12))
            value = c == 10 ? socket->capped : socket->strict;
        else if (b == 1 && c == 3)
            value = socket->type;
        else if (b == 1 && c == 4)
            value = socket->overrun ? 105 : 0;
        else if (b == 1 && c == 38)
            value = socket->protocol;
        else if (socket->protocol == device_events && b == 1 && c == 16)
            value = socket->pass_credentials;
        else if (b == 1 && c == 39)
            value = 16;
        else if (b == 1 && (c == 7 || c == 8))
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
            socket->overrun = false;
        return 0;
    }
    return -95;
}
} // namespace ax

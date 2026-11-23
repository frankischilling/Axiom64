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
constexpr size_t max_buffer_request = 512 * 1024;
constexpr unsigned route_protocol = 0, uevent_protocol = 15, generic_protocol = 16;
constexpr uint32_t kernel_uevent_group = 1, processed_uevent_group = 2;
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
    NetlinkAddress peer{};
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

int netlink_target(Task& task, NetlinkSocket* socket, const NetlinkAddress& address) {
    if (address.family != 16)
        return -22;
    if (socket->protocol == uevent_protocol) {
        if (address.groups && (address.groups != processed_uevent_group || address.port))
            return -95;
        if ((address.groups || address.port) && !capable(task.credentials, Capability::net_admin))
            return -1;
        return 0;
    }
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

size_t netlink_receive_control(Task& task, NetlinkSocket* socket, const NetlinkFrame& frame,
                               uint64_t address, uint64_t capacity, uint32_t& flags) {
    if (!socket->passcred)
        return 0;
    SocketControlWriter writer(task, 1, address, capacity, flags);
    writer.append(2, frame.credentials, sizeof(frame.credentials)); // SCM_CREDENTIALS.
    return writer.used;
}

size_t netlink_available(NetlinkSocket* socket) {
    auto frame = netlink_front(socket);
    return frame ? frame->length : 0;
}

bool netlink_ready(NetlinkSocket* socket, bool write) {
    return write ? socket->count + socket->deliveries < queue_count &&
                       socket->bytes + netlink_ack_size <= socket->receive_limit
                 : socket->count != 0 || socket->error != 0;
}

int netlink_error(NetlinkSocket* socket, bool consume) {
    const int error = socket->error;
    if (consume)
        socket->error = 0;
    return error;
}

static int reserve_frame(NetlinkSocket* socket, size_t length, NetlinkFrame*& frame) {
    if (socket->count + socket->deliveries >= queue_count ||
        socket->bytes > socket->receive_limit || length > socket->receive_limit - socket->bytes)
        return -11;
    frame = static_cast<NetlinkFrame*>(alloc(sizeof(NetlinkFrame) + length));
    if (!frame)
        return -12;
    frame->source = {};
    memset(frame->credentials, 0, sizeof(frame->credentials));
    frame->length = frame->reserved = length;
    ++socket->deliveries;
    socket->bytes += length;
    return 0;
}

static void discard_frame(NetlinkSocket* socket, NetlinkFrame* frame) {
    --socket->deliveries;
    socket->bytes -= frame->reserved;
    release(frame);
}

int netlink_reserve_delivery(NetlinkSocket* socket, size_t length, NetlinkFrame*& frame) {
    // POSIX message queues use route sockets for completion cookies.
    return socket->protocol == route_protocol ? reserve_frame(socket, length, frame) : -95;
}

void netlink_publish_delivery(NetlinkSocket* socket, NetlinkFrame* frame) {
    --socket->deliveries;
    socket->queue[(socket->head + socket->count++) % queue_count] = frame;
}

static int deliver_notification(NetlinkSocket& socket, const void* data, size_t length,
                                const NetlinkAddress& source, const uint32_t* credentials) {
    NetlinkFrame* frame;
    if (int error = reserve_frame(&socket, length, frame))
        return error;
    frame->source = source;
    if (credentials)
        memcpy(frame->credentials, credentials, sizeof(frame->credentials));
    memcpy(frame + 1, data, length);
    netlink_publish_delivery(&socket, frame);
    epoll_notify(socket.handle, 1);
    return 0;
}

static void broadcast_notification(unsigned protocol, const NetlinkSocket* sender, const void* data,
                                   size_t length, const NetlinkAddress& source,
                                   const uint32_t* credentials = nullptr) {
    for (auto& socket : sockets) {
        if (!socket.used || &socket == sender || socket.protocol != protocol ||
            !(socket.groups & source.groups))
            continue;
        if (deliver_notification(socket, data, length, source, credentials)) {
            socket.error = 105; // ENOBUFS: at least one notification was lost.
            epoll_notify(socket.handle, 8);
        }
    }
}

void netlink_broadcast_uevent(const void* data, size_t length) {
    broadcast_notification(uevent_protocol, nullptr, data, length, {16, 0, 0, kernel_uevent_group});
}

void netlink_link_event(const NetInfo& info, uint32_t changed_flags) {
    uint8_t bytes[128];
    size_t length = netlink_format_link_event(info, changed_flags, bytes, sizeof(bytes));
    if (length)
        broadcast_notification(route_protocol, nullptr, bytes, length,
                               {16, 0, 0, netlink_link_group});
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

static int64_t send_uevent(Task& task, NetlinkSocket* sender, const void* data, size_t length,
                           const NetlinkAddress& destination) {
    if (int error = netlink_target(task, sender, destination))
        return error;
    if (!destination.port && !destination.groups)
        return -95;
    if (!sender->port)
        if (int error = bind_port(sender, 0, task.process->pid))
            return error;
    const NetlinkAddress source{16, 0, sender->port, destination.groups};
    const uint32_t credentials[]{uint32_t(task.process->pid), task.credentials.user.real,
                                 task.credentials.group.real};
    if (destination.groups) {
        broadcast_notification(uevent_protocol, sender, data, length, source, credentials);
        return length;
    }
    for (auto& receiver : sockets)
        if (receiver.used && receiver.protocol == uevent_protocol &&
            receiver.port == destination.port) {
            int error = deliver_notification(receiver, data, length, source, credentials);
            if (error)
                return error == -11 ? -105 : error;
            return length;
        }
    return -111;
}

int64_t netlink_send(Task& task, NetlinkSocket* socket, const void* data, size_t length,
                     const NetlinkAddress* destination) {
    if (length > netlink_max_request || length > socket->send_limit - 32)
        return -90;
    if (!length)
        return -61;
    if (socket->protocol == uevent_protocol)
        return send_uevent(task, socket, data, length, destination ? *destination : socket->peer);
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
        error = reserve_frame(socket, reply.capacity, reply.data);
        if (!error && reply.followup)
            error = reserve_frame(socket, netlink_ack_size, reply.end);
        if (!error)
            continue;
        for (size_t j = 0; j <= i; j++) {
            if (replies[j].data)
                discard_frame(socket, replies[j].data);
            if (replies[j].end)
                discard_frame(socket, replies[j].end);
        }
        return error;
    }
    const auto publish = [socket](NetlinkFrame* frame, size_t size) {
        if (!size) {
            discard_frame(socket, frame);
            return;
        }
        frame->length = size;
        netlink_publish_delivery(socket, frame);
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
        publish(reply.data, size);
        if (reply.end)
            publish(reply.end, tail);
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
        if (c != route_protocol && c != generic_protocol && c != uevent_protocol)
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
            if (socket->protocol == uevent_protocol &&
                (address.groups & ~(kernel_uevent_group | processed_uevent_group)))
                return -95;
            if (int error = bind_port(socket, address.port, task.process->pid))
                return error;
            socket->groups = (socket->groups & ~uint64_t(UINT32_MAX)) | address.groups;
            return 0;
        }
        if (int error = netlink_target(task, socket, address))
            return error;
        if (int error = socket->port ? 0 : bind_port(socket, 0, task.process->pid))
            return error;
        socket->peer = {16, 0, address.port, address.groups};
        return 0;
    }
    if (frame.rax == 51 || frame.rax == 52) {
        NetlinkAddress address;
        if (frame.rax == 51) {
            address.port = socket->port;
            address.groups = socket->groups;
        } else
            address = socket->peer;
        return address_out(task, address, b, c);
    }
    if (frame.rax == 54) {
        int value;
        if (frame.r8 < 4)
            return -22;
        if (!task.memory->space.copy_in(&value, d, 4))
            return -14;
        if (socket->protocol == uevent_protocol && b == 1 && (c == 8 || c == 33)) {
            if (c == 33 && !capable(task.credentials, Capability::net_admin))
                return -1;
            if (value < 0)
                return -22;
            socket->receive_limit = max(size_t(256), min(size_t(value) * 2, queue_bytes));
        } else if (socket->protocol == uevent_protocol && b == 270 && (c == 1 || c == 2)) {
            if (value != 1 && value != 2)
                return -22;
            const uint32_t group = 1u << (value - 1);
            if (c == 1)
                socket->groups |= group;
            else
                socket->groups &= ~group;
        } else if (b == 270 && c == 10)
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
            value = netlink_error(socket);
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
        if (b == 1 && c == 4)
            netlink_error(socket, true);
        return 0;
    }
    return -95;
}
} // namespace ax

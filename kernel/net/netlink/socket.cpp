// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/netlink.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr unsigned socket_count = 64, queue_count = 32;
constexpr size_t queue_bytes = 65536;
uint32_t next_port = UINT32_MAX;

size_t aligned(size_t size) {
    return (size + 3) & ~size_t(3);
}
} // namespace

struct NetlinkSocket {
    bool used = false, connected = false, capped = false, strict = false;
    unsigned type = 3, head = 0, count = 0;
    uint32_t port = 0;
    size_t bytes = 0;
    NetlinkFrame* queue[queue_count]{};
};

namespace {
NetlinkSocket sockets[socket_count];

bool occupied(uint32_t port) {
    for (const auto& socket : sockets)
        if (socket.used && socket.port == port)
            return true;
    return false;
}

int bind_port(NetlinkSocket* socket, uint32_t port, unsigned process) {
    if (socket->port)
        return port == socket->port ? 0 : -22;
    if (!port) {
        port = process;
        for (unsigned attempt = 0; occupied(port) && attempt < socket_count; attempt++) {
            port = next_port--;
            if (!next_port)
                next_port = UINT32_MAX;
        }
    }
    if (!port || occupied(port))
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
    return write ? socket->count < queue_count && socket->bytes + 36 <= queue_bytes
                 : socket->count != 0;
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

int64_t netlink_send(NetlinkSocket* socket, unsigned process, const void* data, size_t length) {
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
        capacities[count] = socket->capped && header.type != 26 ? 36 : routing_capacity(header);
        total += capacities[count++];
        if (header.length == length - at)
            break;
        if (aligned(header.length) > length - at)
            return -22;
        at += aligned(header.length);
    }
    if (total > queue_bytes)
        return -90;
    if (count > queue_count - socket->count || total > queue_bytes - socket->bytes)
        return -11;
    int error = socket->port ? 0 : bind_port(socket, 0, process);
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
                          current && capable(current->credentials, Capability::net_admin));
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
        if (c)
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
        if (address.groups)
            return -95;
        if (frame.rax == 49)
            return bind_port(socket, address.port, task.process->pid);
        if (int error = netlink_target(address))
            return error;
        if (int error = socket->port ? 0 : bind_port(socket, 0, task.process->pid))
            return error;
        socket->connected = true;
        return 0;
    }
    if (frame.rax == 51 || frame.rax == 52) {
        NetlinkAddress address;
        address.port = frame.rax == 51 ? socket->port : 0;
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
        else if (b == 1 && (c == 4 || c == 38))
            value = 0;
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
        return 0;
    }
    return -95;
}
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/inet.hpp"
#include "net/ipv4.hpp"
#include "process/task.hpp"

namespace ax {
constexpr unsigned inet_socket_count = 256, inet_queue_count = 32;
constexpr uint32_t inet_queue_bytes = 65536;

struct InetSocket {
    bool used = false, broadcast = false, bound = false;
    unsigned index = 0, head = 0, count = 0;
    uint32_t local = 0, peer = 0, receive_limit = inet_queue_bytes, send_limit = inet_queue_bytes;
    uint32_t filter = 0;
    size_t bytes = 0, transmitted = 0;
    unsigned mtu_policy = 1;
    int error = 0;
    uint8_t ttl = 64;
    uint8_t type = 3, protocol = 1;
    uint16_t peer_port = 0;
    InetFrame* queue[inet_queue_count]{};
};

static InetSocket sockets[inet_socket_count];

bool inet_payload(InetSocket* socket) {
    return socket->type == 3;
}

static uint32_t network_address(uint32_t value) {
    return __builtin_bswap32(value);
}

const InetFrame* inet_front(InetSocket* socket) {
    return socket->count ? socket->queue[socket->head] : nullptr;
}

void inet_consume(InetSocket* socket) {
    if (!socket->count)
        return;
    auto& frame = socket->queue[socket->head];
    socket->bytes -= frame->length;
    release(frame);
    frame = nullptr;
    socket->head = (socket->head + 1) % inet_queue_count;
    socket->count--;
}

void inet_close(InetSocket* socket) {
    ipv4_detach_owner(socket);
    while (socket->count)
        inet_consume(socket);
    socket->used = false;
}

uint32_t inet_peer(InetSocket* socket) {
    return socket->peer;
}

size_t inet_available(InetSocket* socket) {
    auto frame = inet_front(socket);
    return frame ? frame->length : 0;
}

int inet_error(InetSocket* socket, bool clear) {
    if (socket->index && socket->index != ipv4_loopback) {
        const auto info = net_info(socket->index);
        if (!info || !info->live)
            return 5;
    }
    int error = socket->error;
    if (clear)
        socket->error = 0;
    return error;
}

void inet_failed(InetSocket* socket, int error) {
    if (socket && socket->used && !socket->error)
        socket->error = error;
}

void inet_icmp_error(unsigned index, uint32_t local, uint32_t peer, int error) {
    for (auto& socket : sockets)
        if (socket.used && inet_payload(&socket) && socket.peer == peer &&
            (!socket.index || socket.index == index) && socket.local == local)
            inet_failed(&socket, error);
}

void inet_reclaim(InetSocket* socket, size_t length) {
    socket->transmitted -= min(socket->transmitted, length);
}

bool inet_ready(InetSocket* socket, bool write) {
    return !inet_payload(socket) || inet_error(socket) ||
           (write ? ipv4_output_ready() && socket->transmitted < socket->send_limit
                  : socket->count != 0);
}

void inet_deliver(unsigned index, uint32_t source, uint32_t destination, uint8_t protocol,
                  const void* data, size_t length) {
    if (protocol != 1 || length < 28)
        return;
    auto bytes = static_cast<const uint8_t*>(data);
    for (auto& socket : sockets) {
        if (!socket.used || !inet_payload(&socket) || (socket.index && socket.index != index) ||
            (socket.local && socket.local != destination) ||
            (socket.peer && socket.peer != source) ||
            (bytes[20] < 32 && (socket.filter & (uint32_t(1) << bytes[20]))) ||
            socket.count == inet_queue_count ||
            length > socket.receive_limit - min(socket.bytes, size_t(socket.receive_limit)))
            continue;
        auto frame = static_cast<InetFrame*>(alloc(sizeof(InetFrame) + length));
        if (!frame)
            continue;
        *frame = {{2, 0, network_address(source), {}}, length};
        memcpy(frame + 1, data, length);
        socket.queue[(socket.head + socket.count) % inet_queue_count] = frame;
        socket.count++;
        socket.bytes += length;
    }
}

int64_t inet_send(InetSocket* socket, uint32_t destination, const void* data, size_t length) {
    if (!inet_payload(socket))
        return -95;
    if (int error = inet_error(socket, true))
        return -error;
    if (!destination)
        return -89;
    if (length > 65535 - 20 || length + 20 > socket->send_limit)
        return -90;
    if (length + 20 > socket->send_limit - min(socket->transmitted, size_t(socket->send_limit)))
        return -11;
    int error = ipv4_send(socket, socket->local, destination, socket->index, 1, socket->ttl,
                          socket->broadcast, data, length);
    if (!error)
        socket->transmitted += length + 20;
    return error ? error : int64_t(length);
}

int64_t inet_read(InetSocket* socket, void* data, size_t length) {
    if (!inet_payload(socket))
        return -95;
    if (int error = inet_error(socket, true))
        return -error;
    auto frame = inet_front(socket);
    if (!frame)
        return -11;
    size_t copied = min(length, frame->length);
    memcpy(data, inet_bytes(frame), copied);
    inet_consume(socket);
    return copied;
}

static int address_in(Task& task, uint64_t pointer, uint64_t length, InetAddress& address) {
    if (length < sizeof(InetAddress))
        return -22;
    if (!task.memory->space.copy_in(&address, pointer, sizeof(address)))
        return -14;
    return address.family == 2 ? 0 : -97;
}

static int address_out(Task& task, const InetAddress& address, uint64_t pointer,
                       uint64_t length_pointer) {
    uint32_t length, actual = sizeof(address);
    if (!task.memory->space.copy_in(&length, length_pointer, 4) ||
        !task.memory->space.copy_out(pointer, &address, min(length, actual)) ||
        !task.memory->space.copy_out(length_pointer, &actual, 4))
        return -14;
    return 0;
}

int64_t inet_syscall(Task& task, const Frame& frame) {
    auto a = frame.rdi, b = frame.rsi, c = frame.rdx, d = frame.r10;
    auto handle = a < max_fds ? task.files->entries[a].handle : nullptr;
    auto socket = handle ? handle->inet : nullptr;
    if (frame.rax == 41) {
        if (b & ~uint64_t(0x8080f))
            return -22;
        const unsigned type = b & 0xf;
        // Datagram descriptors support configuration ioctls until UDP is implemented.
        if (!((type == 3 && c == 1) || (type == 2 && (c == 0 || c == 17))))
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
        socket->type = type;
        socket->protocol = type == 2 ? 17 : 1;
        auto opened = open_handle(nullptr, 2 | ((b & 0x800) ? 04000 : 0));
        if (!opened) {
            inet_close(socket);
            return -23;
        }
        opened->inet = socket;
        int fd = allocate_fd(&task, opened, 0, b & 0x80000);
        if (fd < 0)
            close_handle(opened);
        return fd;
    }
    if (!socket)
        return -88;
    switch (frame.rax) {
    case 42:
    case 49: {
        if (!inet_payload(socket))
            return -95;
        InetAddress address;
        if (frame.rax == 42 && c >= 2) {
            uint16_t family;
            if (!task.memory->space.copy_in(&family, b, 2))
                return -14;
            if (!family) { // AF_UNSPEC disconnect
                socket->peer = 0;
                socket->peer_port = 0;
                if (!socket->bound)
                    socket->local = 0;
                return 0;
            }
        }
        int error = address_in(task, b, c, address);
        if (error)
            return error;
        uint32_t value = network_address(address.address);
        if (frame.rax == 49) {
            if (value && !ipv4_local(value))
                return -99;
            socket->local = value;
            socket->bound = value != 0;
        } else {
            if (!value)
                return -22;
            uint32_t selected;
            error = ipv4_source(socket->bound ? socket->local : 0, value, socket->index, selected);
            if (error)
                return error;
            socket->local = selected;
            socket->peer = value;
            socket->peer_port = address.port;
        }
        return 0;
    }
    case 51:
    case 52: {
        bool peer = frame.rax == 52;
        if (peer && (!socket->peer || !socket->peer_port))
            return -107;
        InetAddress address{2,
                            uint16_t(peer                ? socket->peer_port
                                     : socket->type == 3 ? 0x0100
                                                         : 0),
                            network_address(peer ? socket->peer : socket->local),
                            {}};
        return address_out(task, address, b, c);
    }
    case 54: {
        if (b == 1 && c == 25) { // SO_BINDTODEVICE
            if (frame.r8 > 16)
                return -22;
            char name[17]{};
            if (!task.memory->space.copy_in(name, d, frame.r8))
                return -14;
            unsigned index = 0;
            if (name[0]) {
                if (!strcmp(name, "lo"))
                    index = ipv4_loopback;
                for (unsigned i = 1; auto info = net_info(i); i++)
                    if (!strcmp(name, info->name))
                        index = i;
                if (!index)
                    return -19;
            }
            socket->index = index;
            return 0;
        }
        int value;
        if (frame.r8 < 4)
            return -22;
        if (!task.memory->space.copy_in(&value, d, 4))
            return -14;
        if (b == 1 && c == 6)
            socket->broadcast = value != 0;
        else if (b == 1 && (c == 7 || c == 8)) {
            if (value < 0)
                return -22;
            uint32_t bound = uint32_t(min(uint64_t(value) * 2, uint64_t(inet_queue_bytes)));
            bound = max(bound, uint32_t(2048));
            (c == 7 ? socket->send_limit : socket->receive_limit) = bound;
        } else if (b == 0 && c == 2) {
            if (value < 1 || value > 255)
                return -22;
            socket->ttl = value;
        } else if (b == 0 && c == 10) {
            if (value != 1 && value != 2)
                return -95;
            socket->mtu_policy = value;
        } else if (b == 255 && c == 1)
            socket->filter = uint32_t(value);
        else
            return -92;
        return 0;
    }
    case 55: {
        uint32_t value = 0, length, actual = 4;
        if (b == 1) {
            if (c == 3)
                value = socket->type;
            else if (c == 4)
                value = inet_error(socket);
            else if (c == 6)
                value = socket->broadcast;
            else if (c == 7)
                value = socket->send_limit;
            else if (c == 8)
                value = socket->receive_limit;
            else if (c == 38)
                value = socket->protocol;
            else if (c == 39)
                value = 2;
            else
                return -92;
        } else if (b == 0 && c == 2)
            value = socket->ttl;
        else if (b == 0 && c == 10)
            value = socket->mtu_policy;
        else if (b == 255 && c == 1)
            value = socket->filter;
        else
            return -92;
        if (!task.memory->space.copy_in(&length, frame.r8, 4) ||
            !task.memory->space.copy_out(d, &value, min(length, actual)) ||
            !task.memory->space.copy_out(frame.r8, &actual, 4))
            return -14;
        if (b == 1 && c == 4)
            socket->error = 0;
        return 0;
    }
    default:
        return -95;
    }
}
} // namespace ax

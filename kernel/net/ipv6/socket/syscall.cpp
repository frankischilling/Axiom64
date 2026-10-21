// SPDX-License-Identifier: GPL-3.0-or-later
#include "../socket.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
int address_in(Task& task, uint64_t pointer, uint32_t length, Inet6Address& address) {
    if (length > 128)
        return -22;
    uint8_t bytes[128];
    if (length && !task.memory->space.copy_in(bytes, pointer, length))
        return -14;
    if (length < 2)
        return -22;
    address = {};
    memcpy(&address, bytes, min(size_t(length), sizeof(address)));
    if (length < sizeof(address))
        address.scope = 0;
    return 0;
}

int output_length(Task& task, uint64_t length_pointer, uint32_t& length) {
    if (!task.memory->space.copy_in(&length, length_pointer, 4))
        return -14;
    return int32_t(length) < 0 ? -22 : 0;
}

int output_bytes(Task& task, const void* bytes, uint32_t actual, uint64_t pointer,
                 uint64_t length_pointer, uint32_t length, bool clamp) {
    uint32_t copied = min(length, actual), reported = clamp ? copied : actual;
    if ((copied && !task.memory->space.copy_out(pointer, bytes, copied)) ||
        !task.memory->space.copy_out(length_pointer, &reported, 4))
        return -14;
    return 0;
}

int output(Task& task, const void* bytes, uint32_t actual, uint64_t pointer,
           uint64_t length_pointer, bool clamp = false) {
    uint32_t length;
    int error = output_length(task, length_pointer, length);
    return error ? error
                 : output_bytes(task, bytes, actual, pointer, length_pointer, length, clamp);
}
} // namespace

int64_t inet6_syscall(Task& task, const Frame& frame) {
    auto a = frame.rdi, b = frame.rsi, c = frame.rdx, d = frame.r10;
    auto handle = a < max_fds ? task.files->entries[a].handle : nullptr;
    auto socket = handle ? handle->inet6 : nullptr;
    if (frame.rax == 41) {
        if (b & ~uint64_t(0x8080f))
            return -22;
        unsigned type = b & 0xf;
        if (type == 3 && !capable(task.credentials, Capability::net_raw))
            return -1;
        if (!((type == 3 && c == 58) || (type == 2 && (c == 0 || c == 17))))
            return -93;
        socket = inet6_allocate(type);
        if (!socket)
            return -23;
        auto opened = open_handle(nullptr, 2 | ((b & 0x800) ? 04000 : 0));
        if (!opened) {
            inet6_close(socket);
            return -23;
        }
        opened->inet6 = socket;
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
        Inet6Address address;
        int error = address_in(task, b, uint32_t(c), address);
        if (error)
            return error;
        if (frame.rax == 42 && !address.family) {
            socket->peer = {};
            socket->peer_port = 0;
            socket->connected = false;
            socket->index = 0;
            if (!socket->bound)
                socket->local = {};
            if (socket->type == 2 && !socket->port_locked)
                socket->local_port = 0;
            socket->error = 0;
            return 0;
        }
        if (uint32_t(c) < 24)
            return -22;
        if (address.family != 10)
            return -97;
        if (address.address.mapped())
            return -101;
        unsigned index = socket->index;
        if (address.address.link_local()) {
            if (frame.rax == 42 && index && address.scope && index != address.scope)
                return -22;
            if (address.scope)
                index = address.scope;
            if (!index)
                return -22;
            if (index != ipv6_loopback && !net_info(index))
                return -19;
        }
        if (frame.rax == 49) {
            if (socket->type == 2 && (socket->local_port || socket->connected))
                return -22;
            if (!address.address.unspecified() && !ipv6_owned(index, address.address))
                return -99;
            if (socket->type == 2) {
                uint16_t port = __builtin_bswap16(address.port);
                if (port && port < 1024 && !capable(task.credentials, Capability::net_bind_service))
                    return -13;
                unsigned previous = socket->index;
                socket->index = index;
                error = inet6_bind_port(socket, address.address, port);
                if (error) {
                    socket->index = previous;
                    return error;
                }
                socket->port_locked = port != 0;
            }
            socket->index = index;
            socket->local = address.address;
            socket->bound = !address.address.unspecified();
        } else {
            if (address.address.unspecified())
                address.address.bytes[15] = 1;
            Ipv6Path path;
            error = ipv6_path(socket->bound ? socket->local : ip6::Address{}, address.address,
                              index, path);
            if (error)
                return error;
            if (socket->type == 2 && !socket->local_port) {
                error = inet6_bind_port(socket, socket->bound ? socket->local : ip6::Address{}, 0);
                if (error)
                    return error;
            }
            socket->local = path.source;
            socket->peer = address.address;
            socket->peer_port = address.port;
            socket->index = index;
            socket->connected = true;
        }
        return 0;
    }
    case 48:
        if (b > 2)
            return -22;
        socket->shutdown |= b == 0 ? 1 : b == 1 ? 2 : 3;
        return socket->connected ? 0 : -107;
    case 51:
    case 52: {
        bool peer = frame.rax == 52;
        if (peer && (!socket->connected || !socket->peer_port))
            return -107;
        auto address =
            peer ? inet6_peer(socket)
                 : Inet6Address{10, __builtin_bswap16(socket->type == 3 ? 58 : socket->local_port),
                                0, socket->local, socket->local.link_local() ? socket->index : 0};
        return output(task, &address, sizeof(address), b, c);
    }
    case 54: {
        uint32_t length = frame.r8;
        if (int32_t(length) < 0)
            return -22;
        if (b == 1 && c == 25) {
            if (length > 16)
                return -22;
            char name[17]{};
            if (length && !task.memory->space.copy_in(name, d, length))
                return -14;
            unsigned index = 0;
            if (name[0]) {
                if (!strcmp(name, "lo"))
                    index = ipv6_loopback;
                for (unsigned n = 1; auto info = net_info(n); n++)
                    if (!strcmp(name, info->name))
                        index = n;
                if (!index)
                    return -19;
            }
            if (socket->index && index != socket->index &&
                !capable(task.credentials, Capability::net_raw))
                return -1;
            socket->index = index;
            return 0;
        }
        if (b == 58 && c == 1 && socket->type == 3) {
            size_t copied = min(size_t(length), sizeof(socket->filter));
            return !copied || task.memory->space.copy_in(socket->filter, d, copied) ? 0 : -14;
        }
        if (b == 41 && (c == 23 || c == 24 || c == 62)) {
            int value = 0;
            size_t copied = length >= 4 && d ? 4 : 0;
            if (copied && !task.memory->space.copy_in(&value, d, copied))
                return -14;
            if (c == 62) {
                socket->dont_fragment = value != 0;
                return 0;
            }
            if (length < 4)
                return -22;
            if (c == 23) {
                if (value < 0 || value > 5)
                    return -22;
                socket->pmtu_mode = value;
            } else {
                if (value && value < int(ip6::minimum_mtu))
                    return -22;
                socket->socket_mtu = value;
            }
            return 0;
        }
        int value;
        if (length < 4)
            return -22;
        if (!task.memory->space.copy_in(&value, d, 4))
            return -14;
        if (b == 1 && c == 2)
            socket->reuse = value != 0;
        else if (b == 1 && (c == 7 || c == 8 || c == 32)) {
            if (c == 32 && !capable(task.credentials, Capability::net_admin))
                return -1;
            if (value < 0 && c != 32)
                return -22;
            uint64_t limit = c == 32  ? uint64_t(INT32_MAX / 2) * 2
                             : c == 7 ? uint64_t(262144)
                                      : uint64_t(inet6_queue_bytes);
            uint32_t bound = max(uint32_t(min(uint64_t(max(value, 0)) * 2, limit)), uint32_t(2048));
            (c == 8 ? socket->receive_limit : socket->send_limit) = bound;
        } else if (b == 41 && c == 16) {
            if (value < -1 || value > 255)
                return -22;
            socket->hops = value == -1 ? 64 : value;
        } else if (b == 41 && c == 26) {
            if (socket->local_port || socket->type == 3)
                return -22;
            socket->v6only = value != 0;
        } else if (b == 41 && c == 7 && socket->type == 3)
            return -22;
        else
            return -92;
        return 0;
    }
    case 55: {
        if (b == 1 && c == 4) {
            uint32_t length;
            int error = output_length(task, frame.r8, length);
            if (error)
                return error;
            int value = inet6_error(socket, true);
            return output_bytes(task, &value, sizeof(value), d, frame.r8, length, true);
        }
        if (b == 58 && c == 1 && socket->type == 3)
            return output(task, socket->filter, sizeof(socket->filter), d, frame.r8, true);
        if (b == 1 && c == 25) {
            const char* name = "";
            if (socket->index == ipv6_loopback)
                name = "lo";
            else if (auto info = net_info(socket->index))
                name = info->name;
            return output(task, name, name[0] ? strlen(name) + 1 : 0, d, frame.r8, true);
        }
        int value;
        if (b == 1) {
            if (c == 2)
                value = socket->reuse;
            else if (c == 3)
                value = socket->type;
            else if (c == 7)
                value = socket->send_limit;
            else if (c == 8)
                value = socket->receive_limit;
            else if (c == 38)
                value = socket->protocol;
            else if (c == 39)
                value = 10;
            else
                return -92;
        } else if (b == 41 && c == 16)
            value = socket->hops;
        else if (b == 41 && c == 23)
            value = socket->pmtu_mode;
        else if (b == 41 && c == 62)
            value = socket->dont_fragment;
        else if (b == 41 && c == 7 && socket->type == 3)
            value = 2;
        else if (b == 41 && c == 26)
            value = socket->v6only;
        else if (b == 41 && c == 24) {
            if (!socket->connected)
                return -107;
            Ipv6Path path;
            int error = ipv6_path(socket->local, socket->peer, socket->index, path);
            if (error)
                return error;
            value = path.mtu;
        } else
            return -92;
        return output(task, &value, sizeof(value), d, frame.r8, true);
    }
    default:
        return -95;
    }
}
} // namespace ax

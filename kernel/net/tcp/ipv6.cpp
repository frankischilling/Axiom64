// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/socket.hpp"
#include "net/ipv4.hpp"
#include "net/socket_options.hpp"
#include "net/ipv6/router.hpp"
#include "process/task.hpp"
#include "io/io.hpp"
#include "../ipv4/socket.hpp"

namespace ax {
int tcp6_import(Task& task, uint64_t pointer, uint32_t length, Inet6Address& address,
                bool connecting) {
    if (length < 2 || length > 128)
        return -22;
    uint8_t bytes[128];
    if (!task.memory->space.copy_in(bytes, pointer, length))
        return -14;
    address = {};
    memcpy(&address, bytes, min(size_t(length), sizeof(address)));
    if (length < sizeof(address))
        address.scope = 0;
    if (connecting && !address.family)
        return 0;
    if (length < 24)
        return -22;
    return address.family == 10 ? 0 : -97;
}

namespace {
int bind(Task& task, InetSocket* socket, const Inet6Address& address) {
    if (socket->local_port || socket->stream || socket->listening)
        return -22;
    const auto& value = address.address;
    bool wire6 = !value.mapped();
    uint32_t local4 = wire6 ? 0 : tcp::Address::ipv6(value).ipv4();
    if (!wire6 && socket->v6only)
        return -22;
    unsigned index = socket->index;
    if (value.link_local()) {
        if (address.scope)
            index = address.scope;
        if (!index)
            return -22;
        if (index != ipv6_loopback && !net_info(index))
            return -19;
    }
    if (wire6 ? (!value.unspecified() && !ipv6_owned(index, value))
              : (local4 && !ipv4_local(local4)))
        return -99;
    uint16_t port = __builtin_bswap16(address.port);
    if (port && port < 1024 && !capable(task.credentials, Capability::net_bind_service))
        return -13;
    auto previous = socket->local6;
    unsigned previous_index = socket->index;
    bool previous_wire = socket->wire6;
    socket->local6 = wire6 ? value : ip6::Address{};
    socket->wire6 = wire6;
    socket->index = index;
    int error = inet_bind_port(socket, local4, port);
    if (error) {
        socket->local6 = previous;
        socket->index = previous_index;
        socket->wire6 = previous_wire;
        return error;
    }
    socket->local = local4;
    socket->bound = wire6 ? !value.unspecified() : local4 != 0;
    if (wire6 && !value.unspecified())
        socket->v6only = true;
    socket->port_locked = port != 0;
    socket->bind_completed = true;
    return 0;
}
} // namespace

int64_t tcp6_syscall(Task& task, const Frame& frame) {
    auto a = frame.rdi, b = frame.rsi, c = frame.rdx;
    if (frame.rax == 41) {
        if (b & ~uint64_t(0x8080f))
            return -22;
        if ((b & 0xf) != 1 || (c != 0 && c != 6))
            return -93;
        auto socket = inet_allocate(1);
        if (!socket)
            return -23;
        socket->ipv6 = socket->wire6 = true;
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
    auto handle = a < max_fds ? task.files->entries[a].handle : nullptr;
    auto socket = handle ? handle->inet : nullptr;
    if (!tcp_ipv6(socket))
        return -88;
    if (frame.rax == 42)
        return io_syscall(task, frame);
    if (frame.rax == 49) {
        Inet6Address address;
        int error = tcp6_import(task, b, uint32_t(c), address, false);
        return error ? error : bind(task, socket, address);
    }
    if (frame.rax == 51 || frame.rax == 52)
        return tcp_address(task, socket, frame.rax == 52, b, c);
    if (b != 41 || (c != 16 && c != 26 && c != 67))
        return -92;
    if (frame.rax == 54) {
        if (int32_t(frame.r8) < 4)
            return -22;
        int value = 0;
        if (frame.r10 && !task.memory->space.copy_in(&value, frame.r10, 4))
            return -14;
        if (c == 26) {
            if (socket->bind_completed || socket->local_port)
                return -22;
            socket->v6only = value != 0;
        } else {
            if (value < -1 || value > 255)
                return -22;
            if (c == 16)
                socket->hops = value;
            else {
                uint8_t selected = (value < 0 ? 0 : value) & ~uint8_t(3);
                selected |= socket->traffic_class & 3;
                if (socket->traffic_class != selected) {
                    socket->traffic_class = selected;
                    ipv6_destination_clear(socket->destination6);
                    socket->destination = {};
                }
            }
        }
        return 0;
    }
    if (frame.rax == 55) {
        uint32_t length;
        if (!task.memory->space.copy_in(&length, frame.r8, 4))
            return -14;
        int value = socket->v6only;
        if (c == 16) {
            unsigned index = socket->destination.path.index;
            value = socket->hops >= 0 ? socket->hops
                    : socket->wire6   ? ipv6_destination_hops(socket->destination6)
                    : index           ? ip6::link_hop_limit(index)
                                      : 64;
        } else if (c == 67)
            value = socket->traffic_class;
        return socket_integer_result(task, value, length, frame.r10, frame.r8);
    }
    return -95;
}
} // namespace ax

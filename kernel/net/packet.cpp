// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/packet.hpp"
#include "process/task.hpp"

namespace ax {
constexpr unsigned packet_queue_size = 32, packet_sockets = 256;
constexpr size_t packet_queue_bytes = 65536;

struct PacketSocket {
    unsigned index = 0, head = 0, count = 0;
    uint16_t protocol = 0;
    bool used = false, ignore_outgoing = false;
    size_t bytes = 0;
    uint32_t packets = 0, dropped = 0;
    PacketFrame* queue[packet_queue_size]{};
};

static PacketSocket sockets[packet_sockets];

static uint16_t network_protocol(uint16_t host) {
    return uint16_t((host << 8) | (host >> 8));
}

void packet_consume(PacketSocket* socket) {
    if (!socket->count)
        return;
    auto& frame = socket->queue[socket->head];
    socket->bytes -= frame->length;
    release(frame);
    frame = nullptr;
    socket->head = (socket->head + 1) % packet_queue_size;
    socket->count--;
}

void packet_close(PacketSocket* socket) {
    while (socket->count)
        packet_consume(socket);
    socket->used = false;
}

const PacketFrame* packet_front(PacketSocket* socket) {
    return socket->count ? socket->queue[socket->head] : nullptr;
}

size_t packet_available(PacketSocket* socket) {
    auto frame = packet_front(socket);
    return frame ? frame->length : 0;
}

unsigned packet_interface(PacketSocket* socket) {
    return socket->index;
}

bool packet_ready(PacketSocket* socket, bool write) {
    const auto info = net_info(socket->index);
    return write ? net_writable(socket->index) : socket->count != 0 || (info && !info->live);
}

void packet_deliver(const NetInfo& info, const void* data, size_t length, unsigned type,
                    const void* sender) {
    const auto bytes = static_cast<const uint8_t*>(data);
    uint16_t protocol;
    memcpy(&protocol, bytes + 12, 2);
    // IEEE 802.3 length fields identify LLC or the historical raw 802.3 protocol.
    if (network_protocol(protocol) < 1536)
        protocol = network_protocol(length >= 16 && bytes[14] == 0xff && bytes[15] == 0xff ? 1 : 4);
    PacketAddress address{17, protocol, int32_t(info.index), 1, uint8_t(type), 6, {}};
    memcpy(address.address, bytes + 6, 6);
    for (auto& socket : sockets) {
        if (!socket.used || &socket == sender || !socket.protocol ||
            (socket.index && socket.index != info.index) ||
            (socket.protocol != network_protocol(3) && socket.protocol != protocol) ||
            (type == 4 && socket.ignore_outgoing))
            continue;
        socket.packets++;
        if (socket.count == packet_queue_size || length > packet_queue_bytes - socket.bytes) {
            socket.dropped++;
            continue;
        }
        auto frame = static_cast<PacketFrame*>(alloc(sizeof(PacketFrame) + length));
        if (!frame) {
            socket.dropped++;
            continue;
        }
        *frame = {address, length};
        memcpy(frame + 1, data, length);
        socket.queue[(socket.head + socket.count) % packet_queue_size] = frame;
        socket.count++;
        socket.bytes += length;
    }
}

int64_t packet_read(PacketSocket* socket, void* data, size_t length) {
    const auto frame = packet_front(socket);
    if (!frame)
        return -11;
    size_t copied = min(length, frame->length);
    memcpy(data, packet_bytes(frame), copied);
    packet_consume(socket);
    return copied;
}

int64_t packet_write(PacketSocket* socket, const void* data, size_t length) {
    int error = socket->index ? net_send(socket->index, data, length, socket) : -6;
    return error ? error : int64_t(length);
}

static int output_address(Task& task, PacketSocket* socket, uint64_t pointer,
                          uint64_t length_pointer) {
    PacketAddress address{17, socket->protocol, int32_t(socket->index), 0, 0, 0, {}};
    auto info = net_info(socket->index);
    if (info) {
        address.hardware = 1;
        address.length = 6;
        memcpy(address.address, info->mac, 6);
    }
    uint32_t length, actual = offsetof(PacketAddress, address) + address.length;
    if (!task.memory->space.copy_in(&length, length_pointer, 4) ||
        !task.memory->space.copy_out(pointer, &address, min(length, actual)) ||
        !task.memory->space.copy_out(length_pointer, &actual, 4))
        return -14;
    return 0;
}

int64_t packet_syscall(Task& task, const Frame& frame) {
    auto a = frame.rdi, b = frame.rsi, c = frame.rdx, d = frame.r10;
    auto handle = a < max_fds ? task.files->entries[a].handle : nullptr;
    auto socket = handle ? handle->packet : nullptr;
    if (frame.rax == 41) {
        if ((b & 0xf) != 3)
            return -95;
        if ((b & ~uint64_t(0x8080f)) || c > UINT16_MAX)
            return -22;
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
        socket->protocol = c;
        auto opened = open_handle(nullptr, 2 | ((b & 0x800) ? 04000 : 0));
        if (!opened) {
            packet_close(socket);
            return -23;
        }
        opened->packet = socket;
        int fd = allocate_fd(&task, opened, 0, b & 0x80000);
        if (fd < 0)
            close_handle(opened);
        return fd;
    }
    if (!socket)
        return -88;
    switch (frame.rax) {
    case 49: {
        PacketAddress address;
        if (c < sizeof(address))
            return -22;
        if (!task.memory->space.copy_in(&address, b, sizeof(address)))
            return -14;
        if (address.family != 17)
            return -22;
        if (address.index && !net_info(address.index))
            return -19;
        socket->index = address.index;
        if (address.protocol)
            socket->protocol = address.protocol;
        return 0;
    }
    case 51:
        return output_address(task, socket, b, c);
    case 54: {
        if (b == 263 && c == 23) {
            int value;
            if (frame.r8 < 4)
                return -22;
            if (!task.memory->space.copy_in(&value, d, 4))
                return -14;
            socket->ignore_outgoing = value != 0;
            return 0;
        }
        return -92;
    }
    case 55: {
        uint32_t values[2]{}, length, actual = 4;
        if (b == 263 && c == 6) { // PACKET_STATISTICS
            values[0] = socket->packets;
            values[1] = socket->dropped;
            actual = 8;
        } else if (b == 1) {
            if (c == 3)
                values[0] = 3;
            else if (c == 4)
                values[0] = 0;
            else if (c == 7 || c == 8)
                values[0] = packet_queue_bytes;
            else if (c == 38)
                values[0] = socket->protocol;
            else if (c == 39)
                values[0] = 17;
            else
                return -92;
        } else
            return -92;
        if (!task.memory->space.copy_in(&length, frame.r8, 4) ||
            !task.memory->space.copy_out(d, values, min(length, actual)) ||
            !task.memory->space.copy_out(frame.r8, &actual, 4))
            return -14;
        if (b == 263 && c == 6)
            socket->packets = socket->dropped = 0;
        return 0;
    }
    default:
        return -95;
    }
}

} // namespace ax

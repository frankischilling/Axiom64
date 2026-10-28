// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket.hpp"
#include "net/socket_control.hpp"

namespace ax {
size_t inet_receive_control(Task& task, InetSocket* socket, const InetFrame& frame,
                            uint64_t address, uint64_t capacity, uint32_t& flags) {
    SocketControlWriter output(task, 0, address, capacity, flags);
    const auto& metadata = frame.metadata;
    if (socket->receive_options.packet_info) {
        struct PacketInfo {
            uint32_t index, specific_destination, destination;
        } info{frame.packet_info_prepared ? metadata.index : 0,
               frame.packet_info_prepared ? __builtin_bswap32(metadata.specific_destination) : 0,
               __builtin_bswap32(metadata.destination)};

        static_assert(sizeof(info) == 12);
        output.append(8, &info, sizeof(info));
    }
    if (socket->receive_options.ttl) {
        int value = metadata.ttl;
        output.append(2, &value, sizeof(value));
    }
    if (socket->receive_options.tos)
        output.append(1, &metadata.tos, sizeof(metadata.tos));
    return output.used;
}
} // namespace ax

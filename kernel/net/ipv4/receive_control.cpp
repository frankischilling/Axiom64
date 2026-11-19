// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/ipv4/receive_control.cpp
 * @brief   IPv4 ancillary receive metadata.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Formats receive metadata such as packet information, TTL, and traffic class
 * in Linux control records.
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
    if (metadata.options.size()) {
        if (socket->receive_options.options)
            output.append(6, metadata.options.data(), metadata.options.size());
        if (socket->receive_options.return_options) {
            if (!metadata.options.return_valid())
                flags |= 8; // MSG_CTRUNC: the return option value cannot be formed.
            else
                output.append(7, metadata.options.reply().data(), metadata.options.reply().size());
        }
    }
    return output.used;
}
} // namespace ax

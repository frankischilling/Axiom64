// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/io/socket_splice.cpp
 * @brief   Socket and pipe data transfers.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Moves bytes through the socket transports and preserves pipe slot ownership.
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

#include "io/socket_splice.hpp"
#include "fs/pipe.hpp"
#include "fs/vfs.hpp"
#include "ipc/ipc.hpp"
#include "net/inet.hpp"
#include "net/inet6.hpp"
#include "net/netlink.hpp"
#include "net/packet.hpp"
#include "net/tcp/socket.hpp"

namespace ax {
static constexpr unsigned socket_pipe_batch = 16;

bool splice_socket(const Handle& handle) {
    return (handle.socket && (handle.socket->type == 1 || handle.socket->type == 2)) ||
           (handle.inet && (inet_stream(handle.inet) || inet_payload(handle.inet))) ||
           handle.inet6 || handle.packet || handle.netlink;
}

int64_t splice_socket_to_pipe(Handle& handle, Pipe& pipe, size_t length) {
    size_t available = socket_pipe_batch * page_size;
    if (handle.socket && handle.socket->type == 2) {
        const uint8_t* bytes;
        size_t packet;
        if (handle.socket->datagrams.front(bytes, packet))
            available = max(size_t(1), packet);
    }
    return copy_handle_to_pipe(handle, pipe, min(length, available));
}

static int64_t send(Task& task, Handle& handle, const void* bytes, size_t length, bool more) {
    if (handle.socket)
        return socket_write(task, handle.socket, bytes, length);
    if (handle.packet)
        return packet_write(handle.packet, bytes, length);
    if (handle.netlink)
        return netlink_send(task, handle.netlink, bytes, length);
    if (handle.inet)
        return inet_send(handle.inet, inet_peer(handle.inet), bytes, length, false, nullptr, more);
    return inet6_send(handle.inet6, inet6_peer(handle.inet6), bytes, length, false, nullptr, more);
}

int64_t splice_pipe_to_socket(Task& task, Pipe& pipe, Handle& handle, size_t length, bool more) {
    auto& first = pipe.slot(0);
    auto bytes = static_cast<const uint8_t*>(physical(first.page)) + first.begin;
    size_t first_length = first.end - first.begin;
    size_t length_to_send = min(length, first_length);
    uint8_t* batch = nullptr;
    if (length > first_length && pipe.occupied > 1) {
        unsigned slots = min(pipe.occupied, socket_pipe_batch);
        for (unsigned i = 1; i < slots && length_to_send < length; ++i) {
            auto& slot = pipe.slot(i);
            length_to_send += min(length - length_to_send, size_t(slot.end - slot.begin));
        }
        batch = static_cast<uint8_t*>(alloc(length_to_send));
        if (!batch)
            return -12;
        for (unsigned i = 0, offset = 0; offset < length_to_send; ++i) {
            auto& slot = pipe.slot(i);
            size_t count = min(length_to_send - offset, size_t(slot.end - slot.begin));
            auto start = static_cast<const uint8_t*>(physical(slot.page)) + slot.begin;
            memcpy(batch + offset, start, count);
            offset += count;
        }
        bytes = batch;
    }
    more |= length_to_send < length && pipe.occupied > socket_pipe_batch;
    auto result = send(task, handle, bytes, length_to_send, more);
    release(batch);
    if (result > 0) {
        size_t remaining = result;
        while (remaining) {
            size_t count = min(remaining, pipe.head_bytes());
            pipe_consume_head(pipe, count);
            remaining -= count;
        }
    }
    return result;
}
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/io/request.hpp
 * @brief   Internal I/O request state.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Shares retained I/O state between general and packet transfers.
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
#pragma once

#include "fs/pipe.hpp"
#include "fs/record_lock.hpp"
#include "io/vectors.hpp"
#include "ipc/ipc.hpp"
#include "ipc/unix_control.hpp"
#include "net/inet.hpp"
#include "net/inet6.hpp"
#include "net/netlink.hpp"
#include "net/packet.hpp"
#include "process/task.hpp"

namespace ax {
using Iovec = IoVector;

struct Message {
    uint64_t name;
    uint32_t name_length, padding;
    uint64_t iov, iov_count, control, control_length;
    uint32_t flags, padding2;
};

static_assert(sizeof(Iovec) == 16 && sizeof(Message) == 56);

constexpr uint64_t max_transfer_count = uint64_t(INT32_MAX) & ~(uint64_t(page_size) - 1);

struct TransferBuffer {
    Pipe pipe;
    PipeSlot slots[16];

    void init() {
        pipe = {};
        pipe.slots = slots;
        pipe.capacity = sizeof(slots) / sizeof(slots[0]);
        pipe.readers = 1;
    }

    void discard() {
        while (pipe.occupied)
            pipe_consume_head(pipe, pipe.head_bytes());
    }
};

struct IoRequest {
    Handle* handle;
    Handle* pipe_target;
    TransferBuffer* sendfile_buffer;
    uint64_t splice_position, output_position;
    Task* record_task = nullptr;
    unsigned record_command = 0;
    RecordFlock record{}, original_record{};
    FileTable* reserved_table = nullptr;
    int reserved_fd = -1;
    Frame call;
    Iovec single, *vectors;
    size_t count;
    size_t cursor, cursor_offset, progress;
    unsigned flags;
    bool write, socket, accept, positioned, locking, connect, started;
    bool timed, stream_blocking;
    bool splice_endpoint_blocking;
    int connect_error;
    uint64_t deadline;
    uint64_t inet_generation;
    PacketAddress destination;
    unsigned destination_index;
    InetAddress inet_destination;
    InetSendControl inet_output;
    Inet6Address inet6_destination;
    Inet6SendControl inet6_output;
    uint8_t* send_control_data;
    bool inet_destination_named;
    bool netlink_destination_named;
    NetlinkAddress netlink_destination;
    uint8_t* packet_data;
    bool packet_ready;
    size_t packet_length;
    uint32_t unix_send_limit;
    UnixDatagramRecord* unix_record;
    UnixMessageCredentials unix_credentials;
    UnixRights* unix_rights;
    UnixAddressValue unix_name;
    UnixDatagramTarget unix_target;
    bool unix_named, unix_write_waited, unix_read_identified, unix_source_captured;
    uint64_t address_pointer, address_length_pointer;
    uint64_t control_pointer, control_capacity;
    uint32_t address_capacity;
    uint64_t event_value;
    bool event_value_ready;
};

namespace io_detail {
inline int import_vectors(Task& task, IoRequest& request, uint64_t pointer, size_t count) {
    if (count > 1024)
        return request.call.rax == 46 || request.call.rax == 47 ? -90 : -22;
    request.count = count;
    if (!count)
        return 0;
    request.vectors = static_cast<Iovec*>(alloc(count * sizeof(Iovec)));
    if (!request.vectors)
        return -12;
    if (!task.memory->space.copy_in(request.vectors, pointer, count * sizeof(Iovec)))
        return -14;
    // Linux limits each operation to MAX_RW_COUNT, including vector operations.
    int64_t capacity = bound_io_vectors(request.vectors, count);
    return capacity < 0 ? int(capacity) : 0;
}

inline int copy_packet(Task& task, IoRequest& request, size_t begin, size_t length,
                       uint8_t* output = nullptr) {
    if (!output)
        output = request.packet_data;
    size_t at = 0, end = begin + length;
    for (size_t i = 0; i < request.count && at < end; i++) {
        const auto& vector = request.vectors[i];
        size_t next = at + vector.length;
        if (next > begin) {
            size_t skip = begin > at ? begin - at : 0;
            size_t copied = min(vector.length - skip, end - at - skip);
            if (copied &&
                (vector.base > UINT64_MAX - skip ||
                 !task.memory->space.copy_in(output + at + skip, vector.base + skip, copied)))
                return -14;
        }
        at = next;
    }
    return 0;
}

inline bool copy_packet_output(Task& task, uint64_t destination, const void* data, size_t length) {
    if (!length)
        return true;
    if (destination >= user_limit || length > user_limit - destination)
        return false;
    auto source = static_cast<const uint8_t*>(data);
    while (length) {
        // Preserve bytes on writable pages before a later output-copy fault.
        size_t count = min(length, size_t(page_size - destination % page_size));
        if (!task.memory->space.copy_out(destination, source, count))
            return false;
        destination += count;
        source += count;
        length -= count;
    }
    return true;
}

} // namespace io_detail
} // namespace ax

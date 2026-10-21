// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket.hpp"

namespace ax {
bool inet6_queue_error(Inet6Socket* socket, const Inet6Error& metadata, const void* bytes,
                       size_t length) {
    if (length > 65535)
        return false;
    size_t cost = sizeof(Inet6Error) + length;
    if (!socket->receive_errors || socket->error_count == inet6_queue_count ||
        cost > socket->receive_limit -
                   min(socket->bytes + socket->error_bytes, size_t(socket->receive_limit)))
        return false;
    auto record = static_cast<Inet6Error*>(alloc(cost));
    if (!record)
        return false;
    *record = metadata;
    record->length = length;
    if (length)
        memcpy(record + 1, bytes, length);
    socket->errors[(socket->error_head + socket->error_count) % inet6_queue_count] = record;
    socket->error_count++;
    socket->error_bytes += cost;
    return true;
}

bool inet6_error_queued(Inet6Socket* socket) {
    return socket->error_count != 0;
}

Inet6Error* inet6_take_error(Inet6Socket* socket) {
    if (!socket->error_count)
        return nullptr;
    auto record = socket->errors[socket->error_head];
    socket->errors[socket->error_head] = nullptr;
    socket->error_head = (socket->error_head + 1) % inet6_queue_count;
    socket->error_count--;
    socket->error_bytes -= sizeof(Inet6Error) + record->length;
    auto next = socket->error_count ? socket->errors[socket->error_head] : nullptr;
    if (next && next->error.origin == 3)
        socket->error = next->error.number;
    else if (record->error.origin == 3)
        socket->error = 0;
    return record;
}

void inet6_purge_errors(Inet6Socket* socket) {
    // Disabling delivery purges records without consuming SO_ERROR.
    for (auto& record : socket->errors) {
        release(record);
        record = nullptr;
    }
    socket->error_head = socket->error_count = 0;
    socket->error_bytes = 0;
}

void inet6_local_error(Inet6Socket* socket, const Inet6Address& requested, uint32_t mtu,
                       const uint8_t* prefix) {
    Inet6Error record;
    record.destination = requested;
    record.destination.flow = 0;
    record.destination.scope = 0;
    if (socket->type == 3 && prefix)
        memcpy(&record.destination.port, prefix, 2);
    record.offender = {};
    record.offender.family = 0;
    record.error = {90, 1, 0, 0, 0, mtu, 0};
    inet6_queue_error(socket, record, nullptr, 0);
}
} // namespace ax

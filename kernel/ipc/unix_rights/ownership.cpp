// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/unix_rights/ownership.cpp
 * @brief   Unix ancillary descriptor ownership.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Retains file descriptions carried by descriptor-passing messages until
 * delivery or discard.
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
#include "ipc/unix_rights.hpp"
#include "fs/vfs.hpp"

namespace ax {
UnixRights* UnixRights::all = nullptr;
unsigned UnixRights::queued_sockets = 0;

UnixRights* UnixRights::create(uint32_t uid) {
    auto result = static_cast<UnixRights*>(alloc(sizeof(UnixRights)));
    if (!result)
        return nullptr;
    *result = {};
    result->uid = uid;
    result->next = all;
    if (all)
        all->previous = result;
    all = result;
    return result;
}

void UnixRights::append(Handle* handle) {
    if (!handle || !handle->references || receiver || count == maximum)
        panic("invalid Unix description capture");
    retain(handle);
    files[count++] = handle;
    if (handle->socket)
        sockets++;
}

int UnixRights::admission(uint64_t limit, bool privileged) const {
    if (privileged)
        return 0;
    uint64_t inflight = 0;
    for (auto entry = all; entry; entry = entry->next)
        if (entry->receiver && entry->uid == uid)
            inflight += entry->count;
    return inflight > limit ? -109 : 0;
}

void UnixRights::enqueue(Socket* socket) {
    if (!socket || receiver || !count)
        panic("invalid Unix description enqueue");
    receiver = socket;
    queued_sockets += sockets;
}

void UnixRights::drop() {
    if (previous)
        previous->next = next;
    else
        all = next;
    if (next)
        next->previous = previous;
    dequeue();
    // Unlink before closing descriptions: closing one can retire another queue.
    unsigned retained = count;
    count = 0;
    for (unsigned index = 0; index < retained; index++)
        close_handle(files[index]);
    release(this);
}

void UnixRights::dequeue() {
    if (receiver) {
        if (queued_sockets < sockets)
            panic("invalid Unix queued reference count");
        queued_sockets -= sockets;
        receiver = nullptr;
    }
}
} // namespace ax

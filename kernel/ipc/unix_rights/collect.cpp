// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/unix_rights/collect.cpp
 * @brief   Unix descriptor cycle collection.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Finds unreachable in-flight descriptor references so queued Unix messages
 * cannot retain a cycle indefinitely.
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
#include "ipc/ipc.hpp"

namespace ax {
void unix_collect_rights() {
    static bool collecting;
    if (collecting || !UnixRights::queued_sockets)
        return;
    collecting = true;

    struct Vertex {
        Handle* handle;
        UnixRights* outgoing;
        unsigned incoming;
        bool reachable;
    };

    static Vertex vertices[max_handles * 2];
    // Visit and clear only the slots populated by this collection.
    static Vertex* occupied[max_handles];
    static Vertex* work[max_handles];
    static Handle* pins[max_handles];
    unsigned vertices_used = 0;
    auto vertex = [&](Handle* handle) -> Vertex& {
        if (!handle || !handle->references)
            panic("dead Unix description graph vertex");
        size_t index = (reinterpret_cast<uintptr_t>(handle) >> 3) % (max_handles * 2);
        while (vertices[index].handle && vertices[index].handle != handle)
            index = (index + 1) % (max_handles * 2);
        if (!vertices[index].handle) {
            if (vertices_used == max_handles)
                panic("Unix description graph exceeds handle pool");
            occupied[vertices_used++] = &vertices[index];
            vertices[index].handle = handle;
        }
        return vertices[index];
    };
    for (auto entry = UnixRights::all; entry; entry = entry->next) {
        if (!entry->receiver)
            continue;
        auto& owner = vertex(entry->receiver->rights_owner());
        entry->collect_next = owner.outgoing;
        owner.outgoing = entry;
        for (unsigned index = 0; index < entry->count; index++)
            vertex(entry->files[index]).incoming++;
    }
    unsigned queued = 0;
    for (unsigned index = 0; index < vertices_used; ++index) {
        auto& entry = *occupied[index];
        if (entry.handle->references < entry.incoming)
            panic("Unix inflight references exceed total references");
        if (entry.handle->references > entry.incoming) {
            entry.reachable = true;
            work[queued++] = &entry;
        }
    }
    for (unsigned at = 0; at < queued; at++)
        for (auto entry = work[at]->outgoing; entry; entry = entry->collect_next)
            for (unsigned index = 0; index < entry->count; index++) {
                auto& target = vertex(entry->files[index]);
                if (!target.reachable) {
                    target.reachable = true;
                    work[queued++] = &target;
                }
            }
    unsigned pinned = 0;
    for (unsigned index = 0; index < vertices_used; ++index) {
        auto& entry = *occupied[index];
        if (!entry.reachable && entry.handle->socket) {
            retain(entry.handle);
            pins[pinned++] = entry.handle;
        }
    }
    // Pin every doomed endpoint before releasing any edge. Close callbacks can
    // clear other queues; the original socket slots must remain valid throughout.
    for (unsigned index = 0; index < pinned; index++) {
        auto socket = pins[index]->socket;
        socket->datagrams.clear();
        socket->stream.clear();
        for (size_t child = 0; child < socket->queue_size; child++)
            socket->queue[(socket->queue_head + child) % 32]->stream.clear();
    }
    for (unsigned index = 0; index < pinned; index++)
        close_handle(pins[index]);
    for (unsigned index = 0; index < vertices_used; ++index)
        *occupied[index] = {};
    collecting = false;
}
} // namespace ax

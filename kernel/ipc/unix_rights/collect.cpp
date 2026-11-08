// SPDX-License-Identifier: GPL-3.0-or-later
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
    static Vertex* work[max_handles];
    static Handle* pins[max_handles];
    for (auto& vertex : vertices)
        vertex = {};
    unsigned vertices_used = 0;
    auto vertex = [&](Handle* handle) -> Vertex& {
        if (!handle || !handle->references)
            panic("dead Unix description graph vertex");
        size_t index = (reinterpret_cast<uintptr_t>(handle) >> 3) % (max_handles * 2);
        while (vertices[index].handle && vertices[index].handle != handle)
            index = (index + 1) % (max_handles * 2);
        if (!vertices[index].handle) {
            if (++vertices_used > max_handles)
                panic("Unix description graph exceeds handle pool");
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
    for (auto& entry : vertices) {
        if (!entry.handle)
            continue;
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
    for (auto& entry : vertices)
        if (entry.handle && !entry.reachable && entry.handle->socket) {
            retain(entry.handle);
            pins[pinned++] = entry.handle;
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
    collecting = false;
}
} // namespace ax

// SPDX-License-Identifier: GPL-3.0-or-later
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

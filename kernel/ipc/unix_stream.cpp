// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/unix_stream.hpp"

namespace ax {
UnixStreamRecord* UnixStreamRecord::create(size_t capacity) {
    if (!capacity || capacity > UnixStreamQueue::capacity)
        return nullptr;
    auto record = static_cast<UnixStreamRecord*>(alloc(sizeof(UnixStreamRecord) + capacity));
    if (record)
        *record = {};
    return record;
}

void UnixStreamRecord::drop() {
    if (following)
        panic("released linked Unix stream interval");
    auto rights = files;
    files = nullptr;
    if (rights)
        rights->drop();
    release(this);
}

void UnixStreamQueue::accept(UnixStreamRecord* record, size_t length,
                             const UnixMessageCredentials& credentials, UnixRights*& rights,
                             Socket* receiver) {
    if (!record || !length || record->length || record->following || length > capacity - bytes)
        panic("invalid Unix stream interval transfer");
    record->length = length;
    record->identity = credentials;
    record->files = rights;
    rights = nullptr;
    if (record->files)
        record->files->enqueue(receiver);
    if (last)
        last->following = record;
    else
        first = record;
    last = record;
    bytes += length;
}

void UnixStreamQueue::consume(size_t count, UnixRights*& rights) {
    if (!first || !count || count > first->size() || rights)
        panic("invalid Unix stream interval consume");
    auto record = first;
    rights = record->files;
    record->files = nullptr;
    if (rights)
        rights->dequeue();
    record->consumed += count;
    bytes -= count;
    if (!record->size()) {
        first = record->following;
        if (!first)
            last = nullptr;
        record->following = nullptr;
        record->drop();
    }
}

void UnixStreamQueue::clear() {
    while (first) {
        UnixRights* rights = nullptr;
        consume(first->size(), rights);
        if (rights)
            rights->drop();
    }
}
} // namespace ax

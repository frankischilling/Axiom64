// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file
 */
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
    if (sender_name)
        sender_name->drop();
    release(this);
}

void UnixStreamQueue::accept(UnixStreamRecord* record, size_t length,
                             const UnixMessageCredentials& credentials, UnixRights*& rights,
                             Socket* receiver, UnixAddressName* source) {
    if (!record || !length || record->length || record->following || length > capacity - bytes)
        panic("invalid Unix stream interval transfer");
    record->length = length;
    record->identity = credentials;
    record->sender_name = source;
    if (source)
        source->retain();
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

void UnixStreamQueue::take_rights(UnixRights*& rights) {
    if (!first || rights)
        panic("invalid Unix stream description transfer");
    rights = first->files;
    first->files = nullptr;
    if (rights)
        rights->dequeue();
}

void UnixStreamQueue::consume(size_t count, UnixRights*& rights) {
    if (!first || !count || count > first->size() || rights)
        panic("invalid Unix stream interval consume");
    auto record = first;
    take_rights(rights);
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

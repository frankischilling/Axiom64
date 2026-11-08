// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/unix_datagram.hpp"

namespace ax {
int UnixDatagramQueue::admission(size_t length) const {
    if (length > byte_limit - 32)
        return -90;
    if (records == record_limit || length + sizeof(Record) > byte_limit - charged)
        return -11;
    return 0;
}

int64_t UnixDatagramQueue::append(const void* bytes, size_t length) {
    if (int error = admission(length))
        return error;
    auto record = static_cast<Record*>(alloc(sizeof(Record) + length));
    if (!record)
        return -12;
    *record = {nullptr, length};
    if (length)
        memcpy(record + 1, bytes, length);
    if (last)
        last->next = record;
    else
        first = record;
    last = record;
    records++;
    charged += sizeof(Record) + length;
    return length;
}

bool UnixDatagramQueue::front(const uint8_t*& bytes, size_t& length) const {
    if (!first)
        return false;
    bytes = reinterpret_cast<const uint8_t*>(first + 1);
    length = first->length;
    return true;
}

void UnixDatagramQueue::consume() {
    if (!first)
        return;
    auto record = first;
    first = record->next;
    if (!first)
        last = nullptr;
    records--;
    charged -= sizeof(Record) + record->length;
    release(record);
}

void UnixDatagramQueue::clear() {
    while (first)
        consume();
}
} // namespace ax

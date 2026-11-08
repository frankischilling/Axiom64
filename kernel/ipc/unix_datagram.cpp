// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/unix_datagram.hpp"

namespace ax {
namespace {
// Charge record bookkeeping and allocator overhead as well as payload bytes.
constexpr size_t record_charge = 64;
} // namespace

uint32_t unix_buffer_size(uint32_t requested, bool sending) {
    return max(min(requested, uint32_t(212992)) * 2, uint32_t(sending ? 4608 : 2304));
}

UnixSendBudget* UnixSendBudget::create() {
    auto budget = static_cast<UnixSendBudget*>(alloc(sizeof(UnixSendBudget)));
    if (budget)
        *budget = {};
    return budget;
}

void UnixSendBudget::drop() {
    if (!--references) {
        if (charged)
            panic("released charged Unix sender");
        release(this);
    }
}

void UnixSendBudget::close() {
    drop();
}

int UnixSendBudget::admission(size_t length) const {
    if (length > limit - 32)
        return -90;
    if (charged >= limit)
        return -11;
    return 0;
}

void UnixSendBudget::resize(uint32_t requested) {
    limit = unix_buffer_size(requested, true);
}

int64_t UnixDatagramQueue::append(UnixSendBudget& owner, const void* bytes, size_t length) {
    static_assert(sizeof(Record) <= record_charge);
    if (int error = owner.admission(length))
        return error;
    auto record = static_cast<Record*>(alloc(sizeof(Record) + length));
    if (!record)
        return -12;
    *record = {nullptr, length, &owner};
    if (length)
        memcpy(record + 1, bytes, length);
    if (last)
        last->next = record;
    else
        first = record;
    last = record;
    owner.references++;
    owner.charged += record_charge + length;
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
    auto owner = record->owner;
    owner->charged -= record_charge + record->length;
    owner->drop();
    release(record);
}

void UnixDatagramQueue::clear() {
    while (first)
        consume();
}
} // namespace ax

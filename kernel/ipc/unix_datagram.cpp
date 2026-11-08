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

int UnixSendBudget::admission(size_t length, uint32_t entry_limit) const {
    if (length > (entry_limit ? entry_limit : limit) - 32)
        return -90;
    if (charged >= limit)
        return -11;
    return 0;
}

void UnixSendBudget::resize(uint32_t requested) {
    limit = unix_buffer_size(requested, true);
}

UnixDatagramRecord* UnixDatagramRecord::create(UnixSendBudget& owner, size_t length, int& error,
                                               uint32_t entry_limit, UnixAddressName* source) {
    static_assert(sizeof(UnixDatagramRecord) <= record_charge);
    error = owner.admission(length, entry_limit);
    if (error)
        return nullptr;
    auto record = static_cast<UnixDatagramRecord*>(alloc(sizeof(UnixDatagramRecord) + length));
    if (!record) {
        error = -12;
        return nullptr;
    }
    *record = {};
    record->length = length;
    record->owner = &owner;
    record->source = source;
    if (source)
        source->retain();
    owner.references++;
    owner.charged += record_charge + length;
    return record;
}

void UnixDatagramRecord::drop() {
    if (queued)
        panic("released queued Unix datagram");
    auto budget = owner;
    auto name = source;
    budget->charged -= record_charge + length;
    if (name)
        name->drop();
    budget->drop();
    release(this);
}

void UnixDatagramQueue::accept(UnixDatagramRecord* record) {
    if (!record || record->queued || record->next)
        panic("invalid Unix datagram transfer");
    record->queued = true;
    if (last)
        last->next = record;
    else
        first = record;
    last = record;
    records++;
}

int64_t UnixDatagramQueue::append(UnixSendBudget& owner, const void* bytes, size_t length,
                                  uint32_t entry_limit, UnixAddressName* source) {
    int error;
    auto record = UnixDatagramRecord::create(owner, length, error, entry_limit, source);
    if (!record)
        return error;
    if (length)
        memcpy(record->data(), bytes, length);
    accept(record);
    return length;
}

bool UnixDatagramQueue::front(const uint8_t*& bytes, size_t& length) const {
    if (!first)
        return false;
    bytes = first->data();
    length = first->length;
    return true;
}

const UnixAddressName* UnixDatagramQueue::source_name() const {
    return first && first->source && first->source->address().length ? first->source : nullptr;
}

void UnixDatagramQueue::consume() {
    if (!first)
        return;
    auto record = first;
    first = record->next;
    if (!first)
        last = nullptr;
    records--;
    record->next = nullptr;
    record->queued = false;
    record->drop();
}

void UnixDatagramQueue::clear() {
    while (first)
        consume();
}
} // namespace ax

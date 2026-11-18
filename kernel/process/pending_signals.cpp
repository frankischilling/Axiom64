// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/pending_signals.hpp"

namespace ax {
struct QueuedSignal {
    QueuedSignal* next;
    SignalData data;
    uint32_t owner;
    int number;
};

namespace {
// Signal records share a pool because the kernel allocator uses at least a page
// per allocation. Access is serialized by the single-CPU scheduler.
QueuedSignal pool[4096];
QueuedSignal* available;
unsigned initialized;

QueuedSignal* allocate(uint32_t uid, uint64_t limit) {
    if (limit != UINT64_MAX) {
        uint64_t charged = 0;
        for (unsigned i = 0; i < initialized; i++)
            if (pool[i].number && pool[i].owner == uid)
                charged++;
        if (charged >= limit)
            return nullptr;
    }
    if (available) {
        auto record = available;
        available = record->next;
        return record;
    }
    return initialized < sizeof(pool) / sizeof(*pool) ? &pool[initialized++] : nullptr;
}

void recycle(QueuedSignal* record) {
    record->number = 0;
    record->next = available;
    available = record;
}
} // namespace

int PendingSignals::push(int number, const SignalData& data, uint32_t uid, uint64_t limit) {
    uint64_t bit = 1ull << (number - 1);
    bool realtime = number >= 32;
    if (!realtime && (mask_ & bit))
        return 0;
    auto record =
        number == 9 ? nullptr : allocate(uid, !realtime && data.code >= 0 ? UINT64_MAX : limit);
    if (!record && realtime && data.code != 0)
        return -11;
    if (record) {
        *record = {nullptr, data, uid, number};
        if (tail_)
            tail_->next = record;
        else
            head_ = record;
        tail_ = record;
    }
    mask_ |= bit;
    return 0;
}

SignalData PendingSignals::take(int number) {
    uint64_t bit = 1ull << (number - 1);
    QueuedSignal* previous = nullptr;
    auto record = head_;
    while (record && record->number != number) {
        previous = record;
        record = record->next;
    }
    mask_ &= ~bit;
    if (!record)
        return {};
    auto data = record->data;
    if (previous)
        previous->next = record->next;
    else
        head_ = record->next;
    if (tail_ == record)
        tail_ = previous;
    for (auto next = record->next; next; next = next->next)
        if (next->number == number) {
            mask_ |= bit;
            break;
        }
    recycle(record);
    return data;
}

void PendingSignals::discard(uint64_t mask) {
    auto record = head_;
    QueuedSignal* previous = nullptr;
    while (record) {
        auto next = record->next;
        if (mask & (1ull << (record->number - 1))) {
            if (previous)
                previous->next = next;
            else
                head_ = next;
            recycle(record);
        } else
            previous = record;
        record = next;
    }
    tail_ = previous;
    mask_ &= ~mask;
}
} // namespace ax

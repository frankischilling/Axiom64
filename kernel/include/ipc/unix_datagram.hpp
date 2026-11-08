// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
// Queued records retain this charge owner independently of the socket slot.
// A closed sender can be reused while its original messages remain queued.
class UnixSendBudget {
    unsigned references = 1;
    size_t charged = 0;
    uint32_t limit = 212992;
    void drop();
    friend class UnixDatagramQueue;

  public:
    static UnixSendBudget* create();
    void close();
    // Retained sends keep their entry size limit while waiting on current pressure.
    int admission(size_t length, uint32_t entry_limit = 0) const;
    void resize(uint32_t requested);

    uint32_t size() const {
        return limit;
    }

    bool writable() const {
        return charged <= limit / 4;
    }
};

uint32_t unix_buffer_size(uint32_t requested, bool sending);

// One record owns its copied bytes, including an empty datagram. A front view
// remains valid until consume/clear; callers serialize queue access.
class UnixDatagramQueue {
    struct Record {
        Record* next;
        size_t length;
        UnixSendBudget* owner;
    };

    Record *first = nullptr, *last = nullptr;

  public:
    int64_t append(UnixSendBudget&, const void*, size_t, uint32_t entry_limit = 0);
    bool front(const uint8_t*& bytes, size_t& length) const;
    void consume();
    void clear();

    bool readable() const {
        return first != nullptr;
    }

    size_t available() const {
        return first ? first->length : 0;
    }
};
} // namespace ax

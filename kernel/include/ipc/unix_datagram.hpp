// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
// One record owns its copied bytes, including an empty datagram. A front view
// remains valid until consume/clear; callers serialize queue access.
class UnixDatagramQueue {
    struct Record {
        Record* next;
        size_t length;
    };

    Record *first = nullptr, *last = nullptr;
    size_t records = 0, charged = 0;

  public:
    static constexpr size_t byte_limit = 212992, record_limit = 128;

    int admission(size_t length) const;
    int64_t append(const void*, size_t);
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

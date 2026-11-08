// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"
#include "ipc/unix_address.hpp"
#include "ipc/unix_credentials.hpp"

namespace ax {
// Queued records retain this charge owner independently of the socket slot.
// A closed sender can be reused while its original messages remain queued.
class UnixSendBudget {
    unsigned references = 1;
    size_t charged = 0;
    uint32_t limit = 212992;
    void drop();
    friend class UnixDatagramQueue;
    friend class UnixDatagramRecord;

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

// A prepared send owns its sender charge even while waiting for a named peer's
// receive queue. Queue insertion transfers ownership without allocation/copying.
class UnixDatagramRecord {
    UnixDatagramRecord* next = nullptr;
    size_t length = 0;
    UnixSendBudget* owner = nullptr;
    UnixAddressName* source = nullptr;
    bool queued = false;
    UnixMessageCredentials message_credentials{};
    friend class UnixDatagramQueue;

  public:
    static UnixDatagramRecord* create(UnixSendBudget&, size_t, int& error, uint32_t entry_limit = 0,
                                      UnixAddressName* source = nullptr);
    void drop();

    uint8_t* data() {
        return reinterpret_cast<uint8_t*>(this + 1);
    }

    size_t size() const {
        return length;
    }

    UnixMessageCredentials& credentials() {
        return message_credentials;
    }
};

// A front view remains valid until consume/clear; callers serialize access.
class UnixDatagramQueue {
    UnixDatagramRecord *first = nullptr, *last = nullptr;
    size_t records = 0;

  public:
    int64_t append(UnixSendBudget&, const void*, size_t, uint32_t entry_limit = 0,
                   UnixAddressName* source = nullptr);
    void accept(UnixDatagramRecord*);
    bool front(const uint8_t*& bytes, size_t& length) const;
    const UnixAddressName* source_name() const;
    const UnixMessageCredentials* credentials() const;
    void consume();
    void clear();

    bool readable() const {
        return first != nullptr;
    }

    size_t available() const {
        return first ? first->length : 0;
    }

    size_t count() const {
        return records;
    }
};
} // namespace ax

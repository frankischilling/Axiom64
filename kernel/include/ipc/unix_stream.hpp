// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"
#include "ipc/unix_credentials.hpp"
#include "ipc/unix_rights.hpp"

namespace ax {
struct Socket;

// Each accepted byte interval owns its sender identity and optional descriptions.
// A partial consuming read detaches descriptions once while preserving the tail.
class UnixStreamRecord {
    UnixStreamRecord* following = nullptr;
    size_t length = 0, consumed = 0;
    UnixMessageCredentials identity{};
    UnixRights* files = nullptr;
    friend class UnixStreamQueue;

  public:
    static UnixStreamRecord* create(size_t capacity);
    void drop();

    uint8_t* data() {
        return reinterpret_cast<uint8_t*>(this + 1) + consumed;
    }

    const uint8_t* data() const {
        return reinterpret_cast<const uint8_t*>(this + 1) + consumed;
    }

    size_t size() const {
        return length - consumed;
    }

    const UnixMessageCredentials& credentials() const {
        return identity;
    }

    const UnixRights* rights() const {
        return files;
    }

    const UnixStreamRecord* next() const {
        return following;
    }
};

class UnixStreamQueue {
    UnixStreamRecord *first = nullptr, *last = nullptr;
    size_t bytes = 0;

  public:
    static constexpr size_t capacity = 65536;

    size_t size() const {
        return bytes;
    }

    const UnixStreamRecord* front() const {
        return first;
    }

    void accept(UnixStreamRecord*, size_t length, const UnixMessageCredentials&, UnixRights*&,
                Socket* receiver);
    // Transfers, rather than destroys, the first consumed description list.
    // The caller must release that list after ancillary output or discard.
    void consume(size_t count, UnixRights*&);
    void clear();
};
} // namespace ax

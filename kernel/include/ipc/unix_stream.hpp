// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/unix_stream.hpp
 * @brief   Unix stream state and operations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the queue and peer interfaces used for stream I/O, readiness, and
 * shutdown.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once
#include "core/base.hpp"
#include "ipc/unix_credentials.hpp"
#include "ipc/unix_rights.hpp"
#include "ipc/unix_address.hpp"

namespace ax {
struct Socket;

// Each accepted byte interval owns its sender identity and optional descriptions.
// A partial consuming read detaches descriptions once while preserving the tail.
class UnixStreamRecord {
    UnixStreamRecord* following = nullptr;
    size_t length = 0, consumed = 0;
    UnixMessageCredentials identity{};
    UnixRights* files = nullptr;
    UnixAddressName* sender_name = nullptr;
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

    const UnixAddressName* source_name() const {
        return sender_name;
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
                Socket* receiver, UnixAddressName* source);
    // Ancillary input can transfer descriptions without consuming a payload byte.
    void take_rights(UnixRights*&);
    // Transfers, rather than destroys, the first consumed description list.
    // The caller must release that list after ancillary output or discard.
    void consume(size_t count, UnixRights*&);
    void clear();
};
} // namespace ax

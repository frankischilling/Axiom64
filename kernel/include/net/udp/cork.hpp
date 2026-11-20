// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/udp/cork.hpp
 * @brief   Pending UDP datagrams.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Owns the payload and first send's controls until a UDP datagram is
 * transmitted or discarded. An output wait preserves the earlier payload.
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
#include <new>

namespace ax {
template <typename Address, typename Control> struct UdpCork {
    Address address;
    Control control;
    bool named;
    uint8_t* control_bytes = nullptr;
    uint8_t* data = nullptr;
    size_t size = 0;
    size_t capacity = 0;

    static UdpCork* create(const Address& address, const Control& control, bool named) {
        auto storage = alloc(sizeof(UdpCork));
        return storage ? new (storage) UdpCork{address, control, named} : nullptr;
    }

    static void discard(UdpCork*& pending) {
        if (!pending)
            return;
        release(pending->control_bytes);
        release(pending->data);
        release(pending);
        pending = nullptr;
    }

    template <typename Emit>
    static int64_t write(UdpCork*& pending, const void* bytes, size_t length, size_t limit,
                         bool more, Emit emit) {
        size_t previous = pending->size;
        if (previous > limit || length > limit - previous) {
            discard(pending);
            return -90;
        }
        size_t total = previous + length;
        if (total > pending->capacity) {
            size_t capacity = min(limit, max(total, pending->capacity * 2));
            auto storage = static_cast<uint8_t*>(alloc(capacity));
            if (!storage) {
                discard(pending);
                return -105;
            }
            if (previous)
                memcpy(storage, pending->data, previous);
            release(pending->data);
            pending->data = storage;
            pending->capacity = capacity;
        }
        if (length)
            memcpy(pending->data + previous, bytes, length);
        if (more) {
            pending->size = total;
            return length;
        }
        int64_t result = emit(*pending, total);
        if (result != -11)
            discard(pending);
        return result < 0 ? result : int64_t(length);
    }
};
} // namespace ax

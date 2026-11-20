// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/unix_address.hpp
 * @brief   Unix socket address interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines local socket address representation and declares parsing and
 * comparison helpers.
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

namespace ax {
// A maximum-length pathname gains a terminating byte on output. Abstract names
// retain every supplied byte, including embedded and trailing zero bytes.
struct UnixAddressValue {
    uint8_t path[109]{};
    uint16_t length = 0;

    bool abstract() const {
        return length && !path[0];
    }

    bool same(const UnixAddressValue&) const;
    bool valid() const;
    // Invalid internal values return zero without touching the destination.
    size_t output(void*, size_t capacity) const;
};

// A family-only input is valid for automatic bind; callers requiring a named
// destination reject its zero path length. Failure leaves the output unchanged.
int unix_address_decode(const void*, size_t, UnixAddressValue&);

// Queued records retain the sender's binding owner even before its first bind.
// One name may be published, then remains immutable. No socket/node is retained.
class UnixAddressName {
    unsigned references = 1;
    UnixAddressValue value;

  public:
    static UnixAddressName* create(const UnixAddressValue&);
    int bind(const UnixAddressValue&);
    void retain();
    void drop();

    const UnixAddressValue& address() const {
        return value;
    }
};
} // namespace ax

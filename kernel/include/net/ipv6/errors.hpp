// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv6/errors.hpp
 * @brief   IPv6 queued error interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines extended error and packet information used when reporting
 * asynchronous socket errors.
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
#include "net/inet6.hpp"

namespace ax {
struct Inet6ExtendedError {
    uint32_t number = 0;
    uint8_t origin = 0, type = 0, code = 0, padding = 0;
    uint32_t information = 0, data = 0;
};

static_assert(sizeof(Inet6ExtendedError) == 16);

struct Inet6Error {
    Inet6Address destination, offender;
    Inet6ExtendedError error;
    ip6::Address packet_destination;
    unsigned index = 0;
    uint8_t hops = 0, traffic_class = 0, extension_protocol = 59;
    size_t length = 0, extension_length = 0;
};

inline const uint8_t* inet6_error_bytes(const Inet6Error* error) {
    return reinterpret_cast<const uint8_t*>(error + 1);
}

// Each queued record owns metadata, payload and outer extensions independently
// of input packets. Extension bytes follow the quoted payload in the allocation.
bool inet6_queue_error(Inet6Socket*, const Inet6Error&, const void*, size_t,
                       const uint8_t* extensions = nullptr);
bool inet6_error_queued(Inet6Socket*);
// Transfers the front record to the caller, including on later user-copy faults.
Inet6Error* inet6_take_error(Inet6Socket*);
void inet6_purge_errors(Inet6Socket*);
void inet6_local_error(Inet6Socket*, const Inet6Address&, uint32_t mtu, const uint8_t* prefix);
} // namespace ax

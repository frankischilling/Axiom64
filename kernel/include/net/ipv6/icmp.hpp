// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv6/icmp.hpp
 * @brief   ICMPv6 interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines ICMPv6 control metadata and declares message generation and
 * processing.
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
#include "net/ipv6/wire.hpp"

namespace ax::ip6 {
struct ErrorQuote {
    // The quoted wire destination keys routes and error-queue addresses.
    // TCP/UDP matching may instead use a validated SRH final destination.
    Address source, destination, transport_destination;
    const uint8_t* transport = nullptr;
    size_t length = 0;
    uint32_t information = 0;
    uint8_t protocol = 0, type = 0, code = 0;
    int error = 0;
    bool hard = false;
};

// Accepts a truncated quote only when its full extension chain and the first
// eight transport bytes are present. The caller owns outer checksum checks.
bool error_quote(const uint8_t*, size_t, ErrorQuote&);
} // namespace ax::ip6

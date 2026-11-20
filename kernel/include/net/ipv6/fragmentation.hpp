// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv6/fragmentation.hpp
 * @brief   IPv6 fragmentation interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares fragment header and payload layout helpers for IPv6 transmission.
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
#include <cstddef>
#include <cstdint>

namespace ax::ip6 {
struct FragmentPiece {
    int error = -22;
    size_t length = 0, consumed = 0;
    bool complete = false;
};

enum class FragmentLayout { protocol, linux_socket };

// Encode one piece of an owned source datagram. Offset counts fragmentable
// bytes accepted by the device; a nonzero offset keeps fragmentation active even
// if the MTU grows. Hop-by-Hop headers and headers through the last Routing header
// repeat before every Fragment header. Later Destination headers are fragmented.
// The first fragment retains the complete extension and upper-layer header chain.
// Every piece retains the same identification. Input and output must not overlap.
// Errors leave output unchanged; existing Fragment, AH and ESP inputs are opaque.
// Linux socket output also repeats Destination options when no Routing header
// exists, matching the observed native datagram layout.
FragmentPiece fragment_packet(const uint8_t*, size_t available, uint32_t mtu, size_t offset,
                              uint32_t identification, uint8_t* output, size_t capacity,
                              FragmentLayout = FragmentLayout::protocol);
} // namespace ax::ip6

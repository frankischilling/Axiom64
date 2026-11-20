// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/fragmentation.hpp
 * @brief   IPv4 fragmentation policy interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines fragment layout decisions and declares helpers for partitioning
 * outbound payloads.
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

namespace ax::ip4 {
struct FragmentPiece {
    int error = -22;
    size_t length = 0, consumed = 0;
    bool complete = false;
};

// Copy the next MTU-bounded IP packet into caller-owned storage. Offset counts
// payload bytes already submitted from this input packet, and must be aligned
// to eight bytes. Advance it only after the driver accepts the returned piece.
// Source and destination storage must not overlap. Input is never modified;
// errors leave output untouched. DF forbids splitting. Existing fragment offsets
// and MF survive re-fragmentation; only copied options survive in later pieces.
FragmentPiece fragment_packet(const uint8_t*, size_t available, size_t mtu, size_t offset,
                              uint8_t* output, size_t capacity);
} // namespace ax::ip4

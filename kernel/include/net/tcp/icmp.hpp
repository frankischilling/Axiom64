// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/tcp/icmp.hpp
 * @brief   TCP ICMP error interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the helpers that match incoming ICMP errors against TCP connection
 * state.
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

namespace ax::tcp {
// An owned description of the minimum ICMP quote. No packet storage is retained.
struct IcmpError {
    uint32_t local = 0, peer = 0, sequence = 0;
    uint16_t source = 0, destination = 0;
    int error = 0;
    bool abort_request = false;
    uint16_t next_hop_mtu = 0, quoted_length = 0;
    bool too_big = false;
};

bool decode_icmp_error(const uint8_t*, size_t, IcmpError&);
// A valid lower IPv4 limit, including legacy zero-MTU notifications; zero means ignore.
uint16_t quoted_path_mtu(const IcmpError&);
} // namespace ax::tcp

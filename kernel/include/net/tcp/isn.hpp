// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/tcp/isn.hpp
 * @brief   TCP initial sequence number interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the generator that combines connection identity with secret and time
 * inputs.
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
#include <cstdint>

namespace ax::ip6 {
struct Address;
}

namespace ax::tcp {
uint32_t initial_sequence(const uint8_t key[32], uint32_t local, uint32_t peer, uint16_t local_port,
                          uint16_t peer_port, uint64_t clock);
// Hash every network-order IPv6 address byte in a separate tuple domain.
// IPv4-mapped streams use their IPv4 wire tuple and the IPv4 overload.
uint32_t initial_sequence(const uint8_t key[32], const ip6::Address& local,
                          const ip6::Address& peer, uint16_t local_port, uint16_t peer_port,
                          uint64_t clock);
} // namespace ax::tcp

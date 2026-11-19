// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/ipv6/socket/receive_control.hpp
 * @brief   IPv6 ancillary receive interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares controls that attach IPv6 packet metadata and extension information
 * to receive messages.
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
#include "../socket.hpp"
#include "net/socket_control.hpp"

namespace ax {
class Inet6ControlWriter : public SocketControlWriter {
  public:
    Inet6ControlWriter(Task& owner, uint64_t pointer, uint64_t limit, uint32_t& result)
        : SocketControlWriter(owner, 41, pointer, limit, result) {
    }

    void metadata(const Inet6Socket*, const ip6::Address& destination, unsigned index, uint8_t hops,
                  uint8_t traffic_class);
    void extensions(const Inet6Socket*, const uint8_t*, size_t length, uint8_t protocol);
    void legacy_metadata(const Inet6Socket*, uint8_t hops);
};
} // namespace ax

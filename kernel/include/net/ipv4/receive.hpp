// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/receive.hpp
 * @brief   IPv4 receive path interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines input packet metadata and declares receive policy hooks.
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
#include "net/ipv4/options.hpp"

namespace ax {
// Input snapshots use host-order IPv4 addresses. No address or route inventory
// entry remains borrowed after the datagram enters a socket queue.
struct Ipv4ReceiveMetadata {
    unsigned index;
    uint32_t source, destination, specific_destination;
    uint8_t protocol, ttl, tos;
    ip4::ReceivedOptions options{};
};

struct Ipv4ReceiveOptions {
    bool packet_info = false, ttl = false, tos = false;
    bool options = false, return_options = false;
};
} // namespace ax

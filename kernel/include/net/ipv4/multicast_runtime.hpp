// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/ipv4/multicast_runtime.hpp
 * @brief   IPv4 multicast runtime interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the multicast worker hooks that apply policy to live devices and
 * sockets.
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
#include "net/ipv4/multicast.hpp"

namespace ax {
struct InetSocket;
struct Task;
struct Frame;
bool ipv4_multicast_member(unsigned index, uint32_t group);
bool ipv4_multicast_source_allowed(unsigned index, uint32_t group, uint32_t source);
bool inet_multicast_accepts(const InetSocket*, unsigned index, uint32_t group, uint32_t source);
void inet_multicast_close(InetSocket*);
bool inet_multicast_loop(const InetSocket*);
int inet_multicast_option(Task&, const Frame&, InetSocket*);
int32_t ipv4_multicast_source_limit();
void ipv4_multicast_source_limit(int32_t);

void ipv4_multicast_poll();
void ipv4_multicast_input(unsigned index, const uint8_t*, size_t);
// Queue a complete owned IGMP frame with Router Alert; never transmits inline.
bool ipv4_multicast_report(unsigned index, uint32_t destination, const uint8_t*, size_t);
} // namespace ax

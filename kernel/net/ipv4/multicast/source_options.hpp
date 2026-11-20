// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/ipv4/multicast/source_options.hpp
 * @brief   IPv4 multicast source option interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares internal socket option handling for IPv4 group and source
 * memberships.
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
struct Task;
struct Frame;
struct InetSocket;
using MulticastInterface = int (*)(unsigned, uint32_t, uint32_t, unsigned&);

// Linux x86-64 source-control layouts, ordered user copies and actual ownership
// updates. Resolution remains with the runtime that owns interfaces and routes.
int multicast_source_option(Task&, const Frame&, InetSocket*, ip4::MulticastHost&,
                            MulticastInterface, unsigned source_limit);
} // namespace ax

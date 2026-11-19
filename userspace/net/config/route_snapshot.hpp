// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/config/route_snapshot.hpp
 * @brief   Route snapshot interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the address and route snapshot read through the userspace
 * configuration tools.
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
#include "net/config/routing.hpp"

namespace ax::net::detail {
// Original main-table records retain attributes across address replacement.
// The enclosing ownership journal bounds the complete persisted intent.
struct RouteSnapshot {
    size_t size = 0;
    uint8_t bytes[4096]{};
};

int decode_route(const void*, size_t, Route&, uint32_t* preferred_source = nullptr);
} // namespace ax::net::detail

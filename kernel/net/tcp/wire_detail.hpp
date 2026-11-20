// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/tcp/wire_detail.hpp
 * @brief   TCP wire implementation helpers.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines internal helpers shared by TCP segment and option codecs.
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
#include "net/tcp/wire.hpp"

namespace ax::tcp::detail {
// Family adapters validate pointer, length and checksum before sharing the parser.
bool decode(const void*, size_t, Segment&);
// Encode the transport once; each family adapter then supplies its pseudo-header checksum.
size_t encode(const Segment&, void*, size_t capacity, size_t maximum);
} // namespace ax::tcp::detail

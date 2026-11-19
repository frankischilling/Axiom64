// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/abi/linux/xattr.hpp
 * @brief   Linux extended-attribute ABI declarations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares Linux path and descriptor operations on filesystem extended
 * attributes.
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

namespace ax {
int64_t linux_xattr(unsigned number, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
} // namespace ax

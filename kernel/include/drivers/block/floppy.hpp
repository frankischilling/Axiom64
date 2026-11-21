// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/block/floppy.hpp
 * @brief   ISA floppy controller interface.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Declares boot-time detection, floppy transfers, and idle motor service.
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
#include "drivers/block/block.hpp"

namespace ax {
constexpr unsigned floppy_slots = 2;
void floppy_init();
const BlockInfo* floppy_info(unsigned);
int floppy_transfer(unsigned, uint64_t, void*, size_t, bool);
void floppy_poll();
} // namespace ax

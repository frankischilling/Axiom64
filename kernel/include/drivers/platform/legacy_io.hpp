// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/legacy_io.hpp
 * @brief   Polled ISA UART and printer interfaces.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Declares the early COM1 console and firmware-assigned legacy device discovery.
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
#include <stddef.h>
#include <stdint.h>

namespace ax {
void serial_init();
void legacy_pnp_init();
bool serial_present();
bool serial_put(char);
int serial_read();

bool parallel_present();
int64_t parallel_write(const void*, size_t);
} // namespace ax

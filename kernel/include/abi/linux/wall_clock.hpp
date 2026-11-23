// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/abi/linux/wall_clock.hpp
 * @brief   Linux wall-clock syscall declarations.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Defines the native guest entry points for authorized wall-clock changes.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once
#include <stdint.h>

namespace ax {
struct Task;

int linux_settimeofday(Task&, uint64_t time, uint64_t timezone);
int linux_clock_settime(Task&, int clock, uint64_t time);
} // namespace ax

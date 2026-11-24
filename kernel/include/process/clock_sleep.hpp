// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/process/clock_sleep.hpp
 * @brief   Linux sleep calls and scheduler wakeups.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Shares sleep deadlines between syscall dispatch, scheduling, and signal delivery.
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
#include <stdint.h>

namespace ax {
struct Task;

int64_t linux_clock_nanosleep(Task&, int clock, int flags, uint64_t request, uint64_t remaining);
bool clock_sleep_resume(Task&);
int clock_sleep_interrupt(Task&);
} // namespace ax

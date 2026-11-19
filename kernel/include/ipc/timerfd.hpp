// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/timerfd.hpp
 * @brief   Timer descriptor interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares timer descriptor state and operations for settings, expirations, and
 * readiness.
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

namespace ax {
struct Handle;
struct Timerfd;

enum class TimerClock { realtime = 0, monotonic = 1, boottime = 7 };

struct TimerfdSetting {
    uint64_t interval, value;
};

Handle* open_timerfd(TimerClock, bool nonblocking, int& error);
void close_timerfd(Timerfd*);
bool timerfd_ready(Timerfd&);
uint64_t timerfd_notification(const Timerfd&);
int64_t timerfd_read(Timerfd&, void*, size_t);
void timerfd_set_ticks(Timerfd&, uint64_t);
TimerfdSetting timerfd_get(Timerfd&);
TimerfdSetting timerfd_set(Timerfd&, TimerfdSetting, bool absolute);
} // namespace ax

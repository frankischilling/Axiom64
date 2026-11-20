// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/net/tcp/time_wait.hpp
 * @brief   TCP TIME_WAIT interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines retained endpoint state and declares TIME_WAIT creation, lookup, and
 * expiry operations.
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

namespace ax::tcp {
// Compact completed sequence space. No application bytes or input pointers remain.
struct TimeWait {
    uint32_t send = 0, receive = 0;
    uint16_t window = 0;
    uint64_t deadline = 0;
};

enum class TimeWaitAction { ignore, acknowledge, remove };

// Input is checksum-validated. Only a duplicate FIN restarts this endpoint's deadline.
TimeWaitAction time_wait_input(TimeWait&, const Segment&, uint64_t now);
} // namespace ax::tcp

// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/platform/poll.hpp
 * @brief   Bounded waits for polled block devices.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Uses elapsed clock ticks and stops if the clock no longer advances.
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
#include "core/time.hpp"

namespace ax::DevicePoll {
template <typename Ready> bool wait(Ready ready, unsigned timeout_ticks) {
    clock_refresh();
    const uint64_t started = ticks;
    uint64_t last_tick = started;
    unsigned stagnant = 0;
    for (uint64_t spins = 0;; ++spins) {
        if (ready())
            return true;
        if ((spins & 255) == 255) {
            clock_refresh();
            if (ticks - started >= timeout_ticks)
                return false;
            if (ticks != last_tick) {
                last_tick = ticks;
                stagnant = 0;
            } else if (++stagnant == 100000)
                return false;
        }
        asm volatile("pause");
    }
}
} // namespace ax::DevicePoll
